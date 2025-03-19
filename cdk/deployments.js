// Copied from https://github.com/aws/aws-cdk/blob/main/packages/aws-cdk/lib/api/cloudformation-deployments.ts
import { randomUUID } from "crypto";
import * as cxapi from "@aws-cdk/cx-api";
import * as cdk_assets from "cdk-assets";
import { AssetManifest } from "cdk-assets";
import { debug, warning } from "sst-aws-cdk/lib/logging.js";
import { EnvironmentAccess } from "sst-aws-cdk/lib/api/environment-access.js";
import { deployStack, destroyStack, } from "./deploy-stack.js";
import { loadCurrentTemplateWithNestedStacks, loadCurrentTemplate, } from "sst-aws-cdk/lib/api/nested-stack-helpers.js";
import { DEFAULT_TOOLKIT_STACK_NAME } from "sst-aws-cdk/lib/api/toolkit-info.js";
import { determineAllowCrossAccountAssetPublishing } from "sst-aws-cdk/lib/api/util/checks.js";
import { CloudFormationStack, stabilizeStack, uploadStackTemplateAssets, } from "sst-aws-cdk/lib/api/util/cloudformation.js";
import { StackActivityMonitor, } from "sst-aws-cdk/lib/api/util/cloudformation/stack-activity-monitor.js";
import { StackEventPoller } from "sst-aws-cdk/lib/api/util/cloudformation/stack-event-poller.js";
import { RollbackChoice } from "sst-aws-cdk/lib/api/util/cloudformation/stack-status.js";
import { makeBodyParameter } from "sst-aws-cdk/lib/api/util/template-body-parameter.js";
import { AssetManifestBuilder } from "sst-aws-cdk/lib/util/asset-manifest-builder.js";
import { buildAssets, EVENT_TO_LOGGER, publishAssets, PublishingAws, } from "sst-aws-cdk/lib/util/asset-publishing.js";
const BOOTSTRAP_STACK_VERSION_FOR_ROLLBACK = 23;
/**
 * Scope for a single set of deployments from a set of Cloud Assembly Artifacts
 *
 * Manages lookup of SDKs, Bootstrap stacks, etc.
 */
export class Deployments {
    props;
    envs;
    /**
     * SDK provider for asset publishing (do not use for anything else).
     *
     * This SDK provider is only allowed to be used for that purpose, nothing else.
     *
     * It's not a different object, but the field name should imply that this
     * object should not be used directly, except to pass to asset handling routines.
     */
    assetSdkProvider;
    /**
     * SDK provider for passing to deployStack
     *
     * This SDK provider is only allowed to be used for that purpose, nothing else.
     *
     * It's not a different object, but the field name should imply that this
     * object should not be used directly, except to pass to `deployStack`.
     */
    deployStackSdkProvider;
    publisherCache = new Map();
    _allowCrossAccountAssetPublishing;
    constructor(props) {
        this.props = props;
        this.assetSdkProvider = props.sdkProvider;
        this.deployStackSdkProvider = props.sdkProvider;
        this.envs = new EnvironmentAccess(props.sdkProvider, props.toolkitStackName ?? DEFAULT_TOOLKIT_STACK_NAME);
    }
    /**
     * Resolves the environment for a stack.
     */
    async resolveEnvironment(stack) {
        return this.envs.resolveStackEnvironment(stack);
    }
    async readCurrentTemplateWithNestedStacks(rootStackArtifact, retrieveProcessedTemplate = false) {
        const env = await this.envs.accessStackForLookupBestEffort(rootStackArtifact);
        return loadCurrentTemplateWithNestedStacks(rootStackArtifact, env.sdk, retrieveProcessedTemplate);
    }
    async readCurrentTemplate(stackArtifact) {
        debug(`Reading existing template for stack ${stackArtifact.displayName}.`);
        const env = await this.envs.accessStackForLookupBestEffort(stackArtifact);
        return loadCurrentTemplate(stackArtifact, env.sdk);
    }
    async resourceIdentifierSummaries(stackArtifact) {
        debug(`Retrieving template summary for stack ${stackArtifact.displayName}.`);
        // Currently, needs to use `deploy-role` since it may need to read templates in the staging
        // bucket which have been encrypted with a KMS key (and lookup-role may not read encrypted things)
        const env = await this.envs.accessStackForReadOnlyStackOperations(stackArtifact);
        const cfn = env.sdk.cloudFormation();
        // @ts-ignore
        await uploadStackTemplateAssets(stackArtifact, this);
        // Upload the template, if necessary, before passing it to CFN
        const builder = new AssetManifestBuilder();
        const cfnParam = await makeBodyParameter(stackArtifact, env.resolvedEnvironment, builder, env.resources);
        // If the `makeBodyParameter` before this added assets, make sure to publish them before
        // calling the API.
        const addedAssets = builder.toManifest(stackArtifact.assembly.directory);
        for (const entry of addedAssets.entries) {
            await this.buildSingleAsset("no-version-validation", addedAssets, entry, {
                stack: stackArtifact,
            });
            await this.publishSingleAsset(addedAssets, entry, {
                stack: stackArtifact,
            });
        }
        const response = await cfn.getTemplateSummary(cfnParam);
        if (!response.ResourceIdentifierSummaries) {
            debug('GetTemplateSummary API call did not return "ResourceIdentifierSummaries"');
        }
        return response.ResourceIdentifierSummaries ?? [];
    }
    async deployStack(options) {
        let deploymentMethod = options.deploymentMethod;
        if (options.changeSetName || options.execute !== undefined) {
            if (deploymentMethod) {
                throw new Error("You cannot supply both 'deploymentMethod' and 'changeSetName/execute'. Supply one or the other.");
            }
            deploymentMethod = {
                method: "change-set",
                changeSetName: options.changeSetName,
                execute: options.execute,
            };
        }
        const env = await this.envs.accessStackForMutableStackOperations(options.stack);
        // Do a verification of the bootstrap stack version
        await this.validateBootstrapStackVersion(options.stack.stackName, options.stack.requiresBootstrapStackVersion, options.stack.bootstrapStackVersionSsmParameter, env.resources);
        const executionRoleArn = await env.replacePlaceholders(options.roleArn ?? options.stack.cloudFormationExecutionRoleArn);
        // Deploy assets
        const assetArtifacts = options.stack.dependencies.filter(cxapi.AssetManifestArtifact.isAssetManifestArtifact);
        for (const asset of assetArtifacts) {
            const manifest = AssetManifest.fromFile(asset.file);
            await publishAssets(manifest, this.deployStackSdkProvider, env.resolvedEnvironment, {
                buildAssets: true,
                allowCrossAccount: true,
                quiet: options.quiet,
                parallel: options.assetParallelism,
            });
        }
        return deployStack({
            stack: options.stack,
            noMonitor: true,
            resolvedEnvironment: env.resolvedEnvironment,
            deployName: options.deployName,
            notificationArns: options.notificationArns,
            quiet: options.quiet,
            sdk: env.sdk,
            sdkProvider: this.deployStackSdkProvider,
            roleArn: executionRoleArn,
            reuseAssets: options.reuseAssets,
            envResources: env.resources,
            tags: options.tags,
            deploymentMethod,
            force: options.force,
            parameters: options.parameters,
            usePreviousParameters: options.usePreviousParameters,
            progress: options.progress,
            ci: options.ci,
            rollback: options.rollback,
            hotswap: options.hotswap,
            hotswapPropertyOverrides: options.hotswapPropertyOverrides,
            extraUserAgent: options.extraUserAgent,
            resourcesToImport: options.resourcesToImport,
            overrideTemplate: options.overrideTemplate,
            assetParallelism: options.assetParallelism,
        });
    }
    async rollbackStack(options) {
        let resourcesToSkip = options.orphanLogicalIds ?? [];
        if (options.force && resourcesToSkip.length > 0) {
            throw new Error("Cannot combine --force with --orphan");
        }
        const env = await this.envs.accessStackForMutableStackOperations(options.stack);
        if (options.validateBootstrapStackVersion ?? true) {
            // Do a verification of the bootstrap stack version
            await this.validateBootstrapStackVersion(options.stack.stackName, BOOTSTRAP_STACK_VERSION_FOR_ROLLBACK, options.stack.bootstrapStackVersionSsmParameter, env.resources);
        }
        const cfn = env.sdk.cloudFormation();
        const deployName = options.stack.stackName;
        // We loop in case of `--force` and the stack ends up in `CONTINUE_UPDATE_ROLLBACK`.
        let maxLoops = 10;
        while (maxLoops--) {
            let cloudFormationStack = await CloudFormationStack.lookup(cfn, deployName);
            const executionRoleArn = await env.replacePlaceholders(options.roleArn ?? options.stack.cloudFormationExecutionRoleArn);
            switch (cloudFormationStack.stackStatus.rollbackChoice) {
                case RollbackChoice.NONE:
                    warning(`Stack ${deployName} does not need a rollback: ${cloudFormationStack.stackStatus}`);
                    return { notInRollbackableState: true };
                case RollbackChoice.START_ROLLBACK:
                    debug(`Initiating rollback of stack ${deployName}`);
                    await cfn.rollbackStack({
                        StackName: deployName,
                        RoleARN: executionRoleArn,
                        ClientRequestToken: randomUUID(),
                        // Enabling this is just the better overall default, the only reason it isn't the upstream default is backwards compatibility
                        RetainExceptOnCreate: true,
                    });
                    break;
                case RollbackChoice.CONTINUE_UPDATE_ROLLBACK:
                    if (options.force) {
                        // Find the failed resources from the deployment and automatically skip them
                        // (Using deployment log because we definitely have `DescribeStackEvents` permissions, and we might not have
                        // `DescribeStackResources` permissions).
                        const poller = new StackEventPoller(cfn, {
                            stackName: deployName,
                            stackStatuses: [
                                "ROLLBACK_IN_PROGRESS",
                                "UPDATE_ROLLBACK_IN_PROGRESS",
                            ],
                        });
                        await poller.poll();
                        resourcesToSkip = poller.resourceErrors
                            .filter((r) => !r.isStackEvent && r.parentStackLogicalIds.length === 0)
                            .map((r) => r.event.LogicalResourceId ?? "");
                    }
                    const skipDescription = resourcesToSkip.length > 0
                        ? ` (orphaning: ${resourcesToSkip.join(", ")})`
                        : "";
                    warning(`Continuing rollback of stack ${deployName}${skipDescription}`);
                    await cfn.continueUpdateRollback({
                        StackName: deployName,
                        ClientRequestToken: randomUUID(),
                        RoleARN: executionRoleArn,
                        ResourcesToSkip: resourcesToSkip,
                    });
                    break;
                case RollbackChoice.ROLLBACK_FAILED:
                    warning(`Stack ${deployName} failed creation and rollback. This state cannot be rolled back. You can recreate this stack by running 'cdk deploy'.`);
                    return { notInRollbackableState: true };
                default:
                    throw new Error(`Unexpected rollback choice: ${cloudFormationStack.stackStatus.rollbackChoice}`);
            }
            const monitor = options.quiet
                ? undefined
                : StackActivityMonitor.withDefaultPrinter(cfn, deployName, options.stack, {
                    ci: options.ci,
                }).start();
            let stackErrorMessage = undefined;
            let finalStackState = cloudFormationStack;
            try {
                const successStack = await stabilizeStack(cfn, deployName);
                // This shouldn't really happen, but catch it anyway. You never know.
                if (!successStack) {
                    throw new Error("Stack deploy failed (the stack disappeared while we were rolling it back)");
                }
                finalStackState = successStack;
                const errors = monitor?.errors?.join(", ");
                if (errors) {
                    stackErrorMessage = errors;
                }
            }
            catch (e) {
                stackErrorMessage = suffixWithErrors(e.message, monitor?.errors);
            }
            finally {
                await monitor?.stop();
            }
            if (finalStackState.stackStatus.isRollbackSuccess || !stackErrorMessage) {
                return { success: true };
            }
            // Either we need to ignore some resources to continue the rollback, or something went wrong
            if (finalStackState.stackStatus.rollbackChoice ===
                RollbackChoice.CONTINUE_UPDATE_ROLLBACK &&
                options.force) {
                // Do another loop-de-loop
                continue;
            }
            throw new Error(`${stackErrorMessage} (fix problem and retry, or orphan these resources using --orphan or --force)`);
        }
        throw new Error("Rollback did not finish after a large number of iterations; stopping because it looks like we're not making progress anymore. You can retry if rollback was progressing as expected.");
    }
    async destroyStack(options) {
        const env = await this.envs.accessStackForMutableStackOperations(options.stack);
        const executionRoleArn = await env.replacePlaceholders(options.roleArn ?? options.stack.cloudFormationExecutionRoleArn);
        return destroyStack({
            sdk: env.sdk,
            roleArn: executionRoleArn,
            stack: options.stack,
            deployName: options.deployName,
            quiet: options.quiet,
            ci: options.ci,
        });
    }
    async stackExists(options) {
        let env;
        if (options.tryLookupRole) {
            env = await this.envs.accessStackForLookupBestEffort(options.stack);
        }
        else {
            env = await this.envs.accessStackForReadOnlyStackOperations(options.stack);
        }
        const stack = await CloudFormationStack.lookup(env.sdk.cloudFormation(), options.deployName ?? options.stack.stackName);
        return stack.exists;
    }
    async prepareAndValidateAssets(asset, options) {
        const env = await this.envs.accessStackForMutableStackOperations(options.stack);
        await this.validateBootstrapStackVersion(options.stack.stackName, asset.requiresBootstrapStackVersion, asset.bootstrapStackVersionSsmParameter, env.resources);
        const manifest = AssetManifest.fromFile(asset.file);
        return { manifest, stackEnv: env.resolvedEnvironment };
    }
    /**
     * Build all assets in a manifest
     *
     * @deprecated Use `buildSingleAsset` instead
     */
    async buildAssets(asset, options) {
        const { manifest, stackEnv } = await this.prepareAndValidateAssets(asset, options);
        await buildAssets(manifest, this.assetSdkProvider, stackEnv, options.buildOptions);
    }
    /**
     * Publish all assets in a manifest
     *
     * @deprecated Use `publishSingleAsset` instead
     */
    async publishAssets(asset, options) {
        const { manifest, stackEnv } = await this.prepareAndValidateAssets(asset, options);
        await publishAssets(manifest, this.assetSdkProvider, stackEnv, {
            ...options.publishOptions,
            allowCrossAccount: await this.allowCrossAccountAssetPublishingForEnv(options.stack),
        });
    }
    /**
     * Build a single asset from an asset manifest
     *
     * If an assert manifest artifact is given, the bootstrap stack version
     * will be validated according to the constraints in that manifest artifact.
     * If that is not necessary, `'no-version-validation'` can be passed.
     */
    // eslint-disable-next-line max-len
    async buildSingleAsset(assetArtifact, assetManifest, asset, options) {
        if (assetArtifact !== "no-version-validation") {
            const env = await this.envs.accessStackForReadOnlyStackOperations(options.stack);
            await this.validateBootstrapStackVersion(options.stack.stackName, assetArtifact.requiresBootstrapStackVersion, assetArtifact.bootstrapStackVersionSsmParameter, env.resources);
        }
        const resolvedEnvironment = await this.envs.resolveStackEnvironment(options.stack);
        const publisher = this.cachedPublisher(assetManifest, resolvedEnvironment, options.stackName);
        await publisher.buildEntry(asset);
    }
    /**
     * Publish a single asset from an asset manifest
     */
    // eslint-disable-next-line max-len
    async publishSingleAsset(assetManifest, asset, options) {
        const stackEnv = await this.envs.resolveStackEnvironment(options.stack);
        // No need to validate anymore, we already did that during build
        const publisher = this.cachedPublisher(assetManifest, stackEnv, options.stackName);
        // eslint-disable-next-line no-console
        await publisher.publishEntry(asset, {
            allowCrossAccount: await this.allowCrossAccountAssetPublishingForEnv(options.stack),
        });
        if (publisher.hasFailures) {
            throw new Error(`Failed to publish asset ${asset.id}`);
        }
    }
    async allowCrossAccountAssetPublishingForEnv(stack) {
        if (this._allowCrossAccountAssetPublishing === undefined) {
            const env = await this.envs.accessStackForReadOnlyStackOperations(stack);
            this._allowCrossAccountAssetPublishing =
                await determineAllowCrossAccountAssetPublishing(env.sdk, this.props.toolkitStackName);
        }
        return this._allowCrossAccountAssetPublishing;
    }
    /**
     * Return whether a single asset has been published already
     */
    async isSingleAssetPublished(assetManifest, asset, options) {
        const stackEnv = await this.envs.resolveStackEnvironment(options.stack);
        const publisher = this.cachedPublisher(assetManifest, stackEnv, options.stackName);
        return publisher.isEntryPublished(asset);
    }
    /**
     * Validate that the bootstrap stack has the right version for this stack
     *
     * Call into envResources.validateVersion, but prepend the stack name in case of failure.
     */
    async validateBootstrapStackVersion(stackName, requiresBootstrapStackVersion, bootstrapStackVersionSsmParameter, envResources) {
        try {
            await envResources.validateVersion(requiresBootstrapStackVersion, bootstrapStackVersionSsmParameter);
        }
        catch (e) {
            throw new Error(`${stackName}: ${e.message}`);
        }
    }
    cachedPublisher(assetManifest, env, stackName) {
        const existing = this.publisherCache.get(assetManifest);
        if (existing) {
            return existing;
        }
        const prefix = stackName ? `${stackName}: ` : "";
        const publisher = new cdk_assets.AssetPublishing(assetManifest, {
            // The AssetPublishing class takes care of role assuming etc, so it's okay to
            // give it a direct `SdkProvider`.
            aws: new PublishingAws(this.assetSdkProvider, env),
            progressListener: new ParallelSafeAssetProgress(prefix, this.props.quiet ?? false),
        });
        this.publisherCache.set(assetManifest, publisher);
        return publisher;
    }
}
/**
 * Asset progress that doesn't do anything with percentages (currently)
 */
class ParallelSafeAssetProgress {
    prefix;
    quiet;
    constructor(prefix, quiet) {
        this.prefix = prefix;
        this.quiet = quiet;
    }
    onPublishEvent(type, event) {
        const handler = this.quiet && type !== "fail" ? debug : EVENT_TO_LOGGER[type];
        handler(`${this.prefix}${type}: ${event.message}`);
    }
}
function suffixWithErrors(msg, errors) {
    return errors && errors.length > 0 ? `${msg}: ${errors.join(", ")}` : msg;
}
