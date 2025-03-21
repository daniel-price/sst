import * as cxapi from "@aws-cdk/cx-api";
import type { Tag } from "@aws-sdk/client-cloudformation";
import type { SDK, SdkProvider } from "sst-aws-cdk/lib/api/aws-auth/index.js";
import type { EnvironmentResources } from "sst-aws-cdk/lib/api/environment-resources.js";
import { HotswapMode, HotswapPropertyOverrides } from "sst-aws-cdk/lib/api/hotswap/common.js";
import { ResourcesToImport } from "sst-aws-cdk/lib/api/util/cloudformation.js";
import { type StackActivityProgress } from "sst-aws-cdk/lib/api/util/cloudformation/stack-activity-monitor.js";
import { StringWithoutPlaceholders } from "sst-aws-cdk/lib/api/util/placeholders.js";
export type DeployStackResult = SuccessfulDeployStackResult | NeedRollbackFirstDeployStackResult | ReplacementRequiresNoRollbackStackResult;
/** Successfully deployed a stack */
export interface SuccessfulDeployStackResult {
    readonly type: "did-deploy-stack";
    readonly noOp: boolean;
    readonly outputs: {
        [name: string]: string;
    };
    readonly stackArn: string;
}
/** The stack is currently in a failpaused state, and needs to be rolled back before the deployment */
export interface NeedRollbackFirstDeployStackResult {
    readonly type: "failpaused-need-rollback-first";
    readonly reason: "not-norollback" | "replacement";
}
/** The upcoming change has a replacement, which requires deploying without --no-rollback */
export interface ReplacementRequiresNoRollbackStackResult {
    readonly type: "replacement-requires-norollback";
}
export declare function assertIsSuccessfulDeployStackResult(x: DeployStackResult): asserts x is SuccessfulDeployStackResult;
export interface DeployStackOptions {
    /**
     * The stack to be deployed
     */
    readonly stack: cxapi.CloudFormationStackArtifact;
    /**
     * Skip monitoring
     */
    readonly noMonitor?: boolean;
    /**
     * The environment to deploy this stack in
     *
     * The environment on the stack artifact may be unresolved, this one
     * must be resolved.
     */
    readonly resolvedEnvironment: cxapi.Environment;
    /**
     * The SDK to use for deploying the stack
     *
     * Should have been initialized with the correct role with which
     * stack operations should be performed.
     */
    readonly sdk: SDK;
    /**
     * SDK provider (seeded with default credentials)
     *
     * Will be used to:
     * - Publish assets, either legacy assets or large CFN templates
     *   that aren't themselves assets from a manifest. (Needs an SDK
     *   Provider because the file publishing role is declared as part
     *   of the asset).
     * - Hotswap
     */
    readonly sdkProvider: SdkProvider;
    /**
     * Information about the bootstrap stack found in the target environment
     */
    readonly envResources: EnvironmentResources;
    /**
     * Role to pass to CloudFormation to execute the change set
     *
     * To obtain a `StringWithoutPlaceholders`, run a regular
     * string though `TargetEnvironment.replacePlaceholders`.
     *
     * @default - No execution role; CloudFormation either uses the role currently associated with
     * the stack, or otherwise uses current AWS credentials.
     */
    readonly roleArn?: StringWithoutPlaceholders;
    /**
     * Notification ARNs to pass to CloudFormation to notify when the change set has completed
     *
     * @default - No notifications
     */
    readonly notificationArns?: string[];
    /**
     * Name to deploy the stack under
     *
     * @default - Name from assembly
     */
    readonly deployName?: string;
    /**
     * Quiet or verbose deployment
     *
     * @default false
     */
    readonly quiet?: boolean;
    /**
     * List of asset IDs which shouldn't be built
     *
     * @default - Build all assets
     */
    readonly reuseAssets?: string[];
    /**
     * Tags to pass to CloudFormation to add to stack
     *
     * @default - No tags
     */
    readonly tags?: Tag[];
    /**
     * What deployment method to use
     *
     * @default - Change set with defaults
     */
    readonly deploymentMethod?: DeploymentMethod;
    /**
     * The collection of extra parameters
     * (in addition to those used for assets)
     * to pass to the deployed template.
     * Note that parameters with `undefined` or empty values will be ignored,
     * and not passed to the template.
     *
     * @default - no additional parameters will be passed to the template
     */
    readonly parameters?: {
        [name: string]: string | undefined;
    };
    /**
     * Use previous values for unspecified parameters
     *
     * If not set, all parameters must be specified for every deployment.
     *
     * @default false
     */
    readonly usePreviousParameters?: boolean;
    /**
     * Display mode for stack deployment progress.
     *
     * @default StackActivityProgress.Bar stack events will be displayed for
     *   the resource currently being deployed.
     */
    readonly progress?: StackActivityProgress;
    /**
     * Deploy even if the deployed template is identical to the one we are about to deploy.
     * @default false
     */
    readonly force?: boolean;
    /**
     * Whether we are on a CI system
     *
     * @default false
     */
    readonly ci?: boolean;
    /**
     * Rollback failed deployments
     *
     * @default true
     */
    readonly rollback?: boolean;
    readonly hotswap?: HotswapMode;
    /**
     * Extra properties that configure hotswap behavior
     */
    readonly hotswapPropertyOverrides?: HotswapPropertyOverrides;
    /**
     * The extra string to append to the User-Agent header when performing AWS SDK calls.
     *
     * @default - nothing extra is appended to the User-Agent header
     */
    readonly extraUserAgent?: string;
    /**
     * If set, change set of type IMPORT will be created, and resourcesToImport
     * passed to it.
     */
    readonly resourcesToImport?: ResourcesToImport;
    /**
     * If present, use this given template instead of the stored one
     *
     * @default - Use the stored template
     */
    readonly overrideTemplate?: any;
    /**
     * Whether to build/publish assets in parallel
     *
     * @default true To remain backward compatible.
     */
    readonly assetParallelism?: boolean;
}
export type DeploymentMethod = DirectDeploymentMethod | ChangeSetDeploymentMethod;
export interface DirectDeploymentMethod {
    readonly method: "direct";
}
export interface ChangeSetDeploymentMethod {
    readonly method: "change-set";
    /**
     * Whether to execute the changeset or leave it in review.
     *
     * @default true
     */
    readonly execute?: boolean;
    /**
     * Optional name to use for the CloudFormation change set.
     * If not provided, a name will be generated automatically.
     */
    readonly changeSetName?: string;
}
export declare function deployStack(options: DeployStackOptions): Promise<DeployStackResult | undefined>;
export interface DestroyStackOptions {
    /**
     * The stack to be destroyed
     */
    stack: cxapi.CloudFormationStackArtifact;
    sdk: SDK;
    roleArn?: string;
    deployName?: string;
    quiet?: boolean;
    ci?: boolean;
}
export declare function destroyStack(options: DestroyStackOptions): Promise<void>;
