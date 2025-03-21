import path from "path";
import fs from "fs";
import { Stack } from "./Stack.js";
import { isSSTConstruct, isStackConstruct, } from "./Construct.js";
import { useFunctions } from "./Function.js";
import { getBindingParameters, getBindingType, } from "./util/binding.js";
import { stack } from "./FunctionalStack.js";
import { Auth } from "./Auth.js";
import { useDeferredTasks } from "./deferred_task.js";
import { provideApp } from "./context.js";
import { useProject } from "../project.js";
import { VisibleError } from "../error.js";
import { Logger } from "../logger.js";
import { App as CDKApp, Tags, CfnResource, RemovalPolicy, CustomResource, Aspects, } from "aws-cdk-lib/core";
import { CfnFunction } from "aws-cdk-lib/aws-lambda";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { Effect, Policy, PolicyStatement } from "aws-cdk-lib/aws-iam";
import { CfnLogGroup } from "aws-cdk-lib/aws-logs";
import { useBootstrap } from "../bootstrap.js";
import { useWarning } from "./util/warning.js";
/**
 * The App construct extends cdk.App and is used internally by SST.
 */
export class App extends CDKApp {
    /**
     * Whether or not the app is running locally under `sst dev`
     */
    local = false;
    /**
     * Whether the app is running locally under start, deploy or remove
     */
    mode;
    /**
     * The name of your app, comes from the `name` in your `sst.config.ts`
     */
    name;
    /**
     * The stage the app is being deployed to. If this is not specified as the --stage option, it'll default to the stage configured during the initial run of the SST CLI.
     */
    stage;
    /**
     * The region the app is being deployed to. If this is not specified as the --region option in the SST CLI, it'll default to the region in your sst.config.ts.
     */
    region;
    /**
     * The AWS account the app is being deployed to. This comes from the IAM credentials being used to run the SST CLI.
     */
    account;
    /** @internal */
    debugScriptVersion;
    /** @internal */
    debugIncreaseTimeout;
    /** @internal */
    appPath;
    /** @internal */
    isActiveStack;
    /** @internal */
    defaultFunctionProps;
    _defaultRemovalPolicy;
    /** @internal */
    get defaultRemovalPolicy() {
        return this._defaultRemovalPolicy;
    }
    /**
     * @internal
     */
    constructor(deployProps, props = {}) {
        super(props);
        provideApp(this);
        this.appPath = process.cwd();
        this.mode = deployProps.mode;
        this.local = this.mode === "dev";
        this.stage = deployProps.stage || "dev";
        this.name = deployProps.name || "my-app";
        this.region =
            deployProps.region || process.env.CDK_DEFAULT_REGION || "us-east-1";
        this.account =
            deployProps.account || process.env.CDK_DEFAULT_ACCOUNT || "my-account";
        this.isActiveStack = deployProps.isActiveStack;
        this.defaultFunctionProps = [];
        this.createTypesFile();
        if (this.mode === "dev") {
            this.debugScriptVersion = deployProps.debugScriptVersion;
            this.debugIncreaseTimeout = deployProps.debugIncreaseTimeout;
        }
    }
    /**
     * Use this method to prefix resource names in your stacks to make sure they don't thrash when deployed to different stages in the same AWS account. This method will prefix a given resource name with the stage and app name. Using the format `${stage}-${name}-${logicalName}`.
     * @example
     * ```js
     * console.log(app.logicalPrefixedName("myTopic"));
     *
     * // dev-my-app-myTopic
     * ```
     */
    logicalPrefixedName(logicalName) {
        const namePrefix = this.name === "" ? "" : `${this.name}-`;
        return `${this.stage}-${namePrefix}${logicalName}`;
    }
    /**
     * The default removal policy that'll be applied to all the resources in the app. This can be useful to set ephemeral (dev or feature branch) environments to remove all the resources on deletion.
     * :::danger
     * Make sure to not set the default removal policy to `DESTROY` for production environments.
     * :::
     * @example
     * ```js
     * app.setDefaultRemovalPolicy(app.mode === "dev" ? "destroy" : "retain")
     * ```
     */
    setDefaultRemovalPolicy(policy) {
        this._defaultRemovalPolicy = policy;
    }
    /**
     * The default function props to be applied to all the Lambda functions in the app. These default values will be overridden if a Function sets its own props.
     * This needs to be called before a stack with any functions have been added to the app.
     *
     * @example
     * ```js
     * app.setDefaultFunctionProps({
     *   runtime: "nodejs20.x",
     *   timeout: 30
     * })
     * ```
     */
    setDefaultFunctionProps(props) {
        this.defaultFunctionProps.push(props);
    }
    /**
     * Adds additional default Permissions to be applied to all Lambda functions in the app.
     *
     * @example
     * ```js
     * app.addDefaultFunctionPermissions(["s3"])
     * ```
     */
    addDefaultFunctionPermissions(permissions) {
        this.defaultFunctionProps.push({
            permissions,
        });
    }
    /**
     * Adds additional default environment variables to be applied to all Lambda functions in the app.
     *
     * @example
     * ```js
     * app.addDefaultFunctionEnv({
     *   "MY_ENV_VAR": "my-value"
     * })
     * ```
     */
    addDefaultFunctionEnv(environment) {
        this.defaultFunctionProps.push({
            environment,
        });
    }
    /**
     * Binds additional default resources to be applied to all Lambda functions in the app.
     *
     * @example
     * ```js
     * app.addDefaultFunctionBinding([STRIPE_KEY, bucket]);
     * ```
     */
    addDefaultFunctionBinding(bind) {
        this.defaultFunctionProps.push({ bind });
    }
    /**
     * Adds additional default layers to be applied to all Lambda functions in the stack.
     */
    addDefaultFunctionLayers(layers) {
        this.defaultFunctionProps.push({
            layers,
        });
    }
    useTypesPath() {
        const project = useProject();
        return path.resolve(project.paths.out, "types");
    }
    createTypesFile() {
        const typesPath = this.useTypesPath();
        Logger.debug(`Generating types in ${typesPath}`);
        fs.rmSync(typesPath, {
            recursive: true,
            force: true,
        });
        fs.mkdirSync(typesPath, {
            recursive: true,
        });
        fs.appendFileSync(`${typesPath}/index.ts`, [
            `import "sst/node/config";`,
            `declare module "sst/node/config" {`,
            `  export interface ConfigTypes {`,
            `    APP: string;`,
            `    STAGE: string;`,
            `  }`,
            `}`,
            ``,
            ``,
        ].join("\n"));
    }
    registerTypes(c) {
        const typesPath = this.useTypesPath();
        if ("_doNotAllowOthersToBind" in c && c._doNotAllowOthersToBind) {
            return;
        }
        const binding = getBindingType(c);
        if (!binding) {
            return;
        }
        const className = c.constructor.name;
        const id = c.id;
        fs.appendFileSync(`${typesPath}/index.ts`, (binding.variables[0] === "."
            ? // Case: variable does not have properties, ie. Secrets and Parameters
                [
                    `import "sst/node/${binding.clientPackage}";`,
                    `declare module "sst/node/${binding.clientPackage}" {`,
                    `  export interface ${className}Resources {`,
                    `    "${id}": string;`,
                    `  }`,
                    `}`,
                    ``,
                    ``,
                ]
            : [
                `import "sst/node/${binding.clientPackage}";`,
                `declare module "sst/node/${binding.clientPackage}" {`,
                `  export interface ${className}Resources {`,
                `    "${id}": {`,
                ...binding.variables.map((p) => `      ${p}: string;`),
                `    }`,
                `  }`,
                `}`,
                ``,
                ``,
            ]).join("\n"));
    }
    isFinished = false;
    async finish() {
        if (this.isFinished)
            return;
        this.isFinished = true;
        const { config, paths } = useProject();
        Auth.injectConfig();
        this.ensureUniqueConstructIds();
        // Run deferred tasks
        // - After codegen b/c some frontend frameworks (ie. Next.js apps) runs
        //   type checking in the build step
        // - Before remove govcloud unsupported resource properties b/c deferred
        //   tasks may add govcloud unsupported resource properties
        await useDeferredTasks().run();
        // Build constructs metadata after running deferred tasks
        // - Metadata for Functions needs to know if sourcemaps are enabled, which
        //   is not known until after build
        this.buildConstructsMetadata();
        this.createBindingSsmParameters();
        this.removeGovCloudUnsupportedResourceProperties();
        useWarning().print();
        for (const child of this.node.children) {
            if (isStackConstruct(child)) {
                // Tag stacks
                Tags.of(child).add("sst:app", this.name);
                Tags.of(child).add("sst:stage", this.stage);
                if (child instanceof Stack &&
                    !this.isRunningSSTTest() &&
                    this.mode !== "dev") {
                    const bootstrap = await useBootstrap();
                    const functions = useFunctions();
                    const sourcemaps = functions.sourcemaps.forStack(child.stackName);
                    if (sourcemaps.length) {
                        // Add policy with access to buckets: CKD bootstrap and SST sourcemap
                        // If the object in CDK bootstrap has tags, target object will have the same tags
                        const policy = new Policy(child, "SourcemapUploaderPolicy", {
                            statements: [
                                new PolicyStatement({
                                    effect: Effect.ALLOW,
                                    actions: [
                                        "s3:GetObject",
                                        "s3:GetObjectTagging",
                                        "s3:PutObject",
                                        "s3:PutObjectTagging",
                                    ],
                                    resources: [
                                        sourcemaps[0].asset.bucket.bucketArn + "/*",
                                        `arn:${child.partition}:s3:::${bootstrap.bucket}/*`,
                                    ],
                                }),
                            ],
                        });
                        child.customResourceHandler.role?.attachInlinePolicy(policy);
                        const resource = new CustomResource(child, "SourcemapUploader", {
                            serviceToken: child.customResourceHandler.functionArn,
                            resourceType: "Custom::SourcemapUploader",
                            properties: {
                                app: this.name,
                                stage: this.stage,
                                tarBucket: bootstrap.bucket,
                                srcBucket: sourcemaps[0].asset.bucket.bucketName,
                                sourcemaps: sourcemaps.map((s) => [
                                    s.tarKey,
                                    s.asset.s3ObjectKey,
                                ]),
                            },
                        });
                        resource.node.addDependency(policy);
                    }
                }
                // Set removal policy
                this.applyRemovalPolicy(child);
                // Stack names need to be parameterized with the stage name
                if (config.advanced?.disableParameterizedStackNameCheck !== true &&
                    !child.stackName.startsWith(`${this.stage}-`) &&
                    !child.stackName.endsWith(`-${this.stage}`) &&
                    child.stackName.indexOf(`-${this.stage}-`) === -1) {
                    throw new Error(`Stack "${child.stackName}" is not parameterized with the stage name. The stack name needs to either start with "$stage-", end in "-$stage", or contain the stage name "-$stage-".`);
                }
            }
        }
    }
    isRunningSSTTest() {
        return process.env.NODE_ENV === "test";
    }
    getInputFilesFromEsbuildMetafile(file) {
        let metaJson;
        try {
            metaJson = JSON.parse(fs.readFileSync(file).toString());
        }
        catch (e) {
            throw new VisibleError("There was a problem reading the esbuild metafile.");
        }
        return Object.keys(metaJson.inputs).map((input) => path.resolve(input));
    }
    createBindingSsmParameters() {
        class CreateSsmParameters {
            visit(c) {
                if (!isSSTConstruct(c))
                    return;
                if ("_doNotAllowOthersToBind" in c && c._doNotAllowOthersToBind)
                    return;
                getBindingParameters(c);
            }
        }
        Aspects.of(this).add(new CreateSsmParameters());
    }
    buildConstructsMetadata() {
        const constructs = this.buildConstructsMetadata_collectConstructs(this);
        const byStack = {};
        const local = [];
        for (const c of constructs) {
            const stack = Stack.of(c);
            const list = byStack[stack.node.id] || [];
            const metadata = c.getConstructMetadata();
            const item = {
                id: c.node.id,
                addr: c.node.addr,
                stack: Stack.of(c).stackName,
                ...metadata,
            };
            local.push(item);
            list.push({
                ...item,
                local: undefined,
            });
            byStack[stack.node.id] = list;
        }
        // Register constructs
        for (const child of this.node.children) {
            if (child instanceof Stack) {
                const stackName = child.node.id;
                child.addOutputs({
                    SSTMetadata: JSON.stringify({
                        app: this.name,
                        stage: this.stage,
                        version: useProject().version,
                        metadata: byStack[stackName] || [],
                    }),
                });
            }
        }
    }
    buildConstructsMetadata_collectConstructs(construct) {
        return [
            isSSTConstruct(construct) ? construct : undefined,
            ...construct.node.children.flatMap((c) => this.buildConstructsMetadata_collectConstructs(c)),
        ].filter((c) => Boolean(c));
    }
    applyRemovalPolicy(current) {
        if (!this._defaultRemovalPolicy)
            return;
        // Apply removal policy to all resources
        if (current instanceof CfnResource) {
            current.applyRemovalPolicy(RemovalPolicy[this._defaultRemovalPolicy.toUpperCase()]);
        }
        // Remove S3 objects on destroy
        if (this._defaultRemovalPolicy === "destroy" &&
            current instanceof Bucket &&
            !current.node.tryFindChild("AutoDeleteObjectsCustomResource")) {
            // Calling a private method here. It's the easiest way to lazily
            // enable auto-delete.
            // @ts-expect-error
            current.enableAutoDeleteObjects();
        }
        current.node.children.forEach((resource) => this.applyRemovalPolicy(resource));
    }
    removeGovCloudUnsupportedResourceProperties() {
        if (!this.region.startsWith("us-gov-")) {
            return;
        }
        class RemoveGovCloudUnsupportedResourceProperties {
            visit(node) {
                if (node instanceof CfnFunction) {
                    node.addPropertyDeletionOverride("EphemeralStorage");
                }
                else if (node instanceof CfnLogGroup) {
                    node.addPropertyDeletionOverride("Tags");
                }
            }
        }
        Aspects.of(this).add(new RemoveGovCloudUnsupportedResourceProperties());
    }
    ensureUniqueConstructIds() {
        // "ids" has the shape of:
        // {
        //   Table: {
        //     "id_with_hyphen": "id-with-hyphen",
        //     "id_with_underscore": "id_with_underscore",
        //   }
        // }
        const ids = {};
        class EnsureUniqueConstructIds {
            visit(c) {
                if (!isSSTConstruct(c))
                    return;
                if ("_doNotAllowOthersToBind" in c && c._doNotAllowOthersToBind)
                    return;
                const className = c.constructor.name;
                const id = c.id;
                const normId = id.replace(/-/g, "_");
                const existingIds = ids[className] || {};
                if (!id.match(/^[a-zA-Z]([a-zA-Z0-9-_])*$/)) {
                    throw new Error([
                        `Invalid id "${id}" for ${className} construct.`,
                        ``,
                        `Starting v1.16, construct ids can only contain alphabetic characters, hyphens ("-"), and underscores ("_"), and must start with an alphabetic character. If you are migrating from version 1.15 or earlier, please see the upgrade guide — https://docs.serverless-stack.com/upgrade-guide#upgrade-to-v116`,
                    ].join("\n"));
                }
                else if (["Parameter", "Secret"].includes(className)) {
                    const existingConfigId = ids.Secret?.[normId] || ids.Parameter?.[normId];
                    if (existingConfigId === id) {
                        throw new Error(`ERROR: Config with id "${id}" already exists.`);
                    }
                    else if (existingConfigId) {
                        throw new Error(`ERROR: You cannot have the same Config id with an underscore and hyphen: "${existingConfigId}" and "${id}".`);
                    }
                }
                else if (existingIds[normId]) {
                    throw new Error([
                        existingIds[normId] === id
                            ? `${className} with id "${id}" already exists.`
                            : `You cannot have the same ${className} id with an underscore and hyphen: "${existingIds[normId]}" and "${id}".`,
                        ``,
                        `Starting v1.16, constructs must have unique ids for a given construct type. If you are migrating from version 1.15 or earlier, set the "cdk.id" in the construct with the existing id, and pick a unique id for the construct. Please see the upgrade guide — https://docs.serverless-stack.com/upgrade-guide#upgrade-to-v116`,
                        ``,
                        `    For example, if you have two Bucket constructs with the same id:`,
                        `      new Bucket(this, "bucket");`,
                        `      new Bucket(this, "bucket");`,
                        ``,
                        `    Change it to:`,
                        `      new Bucket(this, "usersBucket", {`,
                        `        cdk: {`,
                        `          id: "bucket"`,
                        `        }`,
                        `      });`,
                        `      new Bucket(this, "adminBucket", {`,
                        `        cdk: {`,
                        `          id: "bucket"`,
                        `        }`,
                        `      });`,
                    ].join("\n"));
                }
                existingIds[normId] = id;
                ids[className] = existingIds;
            }
        }
        Aspects.of(this).add(new EnsureUniqueConstructIds());
    }
    foreachConstruct(fn) {
        const loop = (parent) => {
            for (const child of parent.node.children) {
                fn(child);
                loop(child);
            }
        };
        for (const child of this.node.children) {
            if (child instanceof Stack) {
                loop(child);
            }
        }
    }
    // Functional Stack
    // This is a magical global to avoid having to pass app everywhere.
    // We only every have one instance of app
    stack(fn, props) {
        return stack(this, fn, props);
    }
}
