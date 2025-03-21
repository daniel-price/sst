/* eslint-disable @typescript-eslint/ban-types */
// Note: disabling ban-type rule so we don't get an error referencing the class Function
import path from "path";
import fs from "fs/promises";
import zlib from "zlib";
import { Stack } from "./Stack.js";
import { Job } from "./Job.js";
import { Secret } from "./Config.js";
import { isSSTConstruct } from "./Construct.js";
import { toCdkSize } from "./util/size.js";
import { toCdkDuration } from "./util/duration.js";
import { getBindingEnvironments, getBindingPermissions, getBindingReferencedSecrets, } from "./util/binding.js";
import { attachPermissionsToRole } from "./util/permission.js";
import * as functionUrlCors from "./util/functionUrlCors.js";
import url from "url";
import { useDeferredTasks } from "./deferred_task.js";
import { useProject } from "../project.js";
import { VisibleError } from "../error.js";
import { useRuntimeHandlers } from "../runtime/handlers.js";
import { createAppContext } from "./context.js";
import { useWarning } from "./util/warning.js";
import { Architecture, AssetCode, Code, Function as CDKFunction, FunctionUrlAuthType, Handler as CDKHandler, LayerVersion, Runtime as CDKRuntime, Tracing, InvokeMode, } from "aws-cdk-lib/aws-lambda";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import { Token, Size as CDKSize, Duration as CDKDuration, IgnoreMode, CustomResource, } from "aws-cdk-lib/core";
import { Effect, Policy, PolicyStatement } from "aws-cdk-lib/aws-iam";
import { StringParameter } from "aws-cdk-lib/aws-ssm";
import { Platform } from "aws-cdk-lib/aws-ecr-assets";
import { useBootstrap } from "../bootstrap.js";
import { Colors } from "../cli/colors.js";
import { Asset } from "aws-cdk-lib/aws-s3-assets";
import { Config } from "../config.js";
const __dirname = url.fileURLToPath(new URL(".", import.meta.url));
const supportedRuntimes = {
    container: CDKRuntime.FROM_IMAGE,
    rust: CDKRuntime.PROVIDED_AL2023,
    "nodejs16.x": CDKRuntime.NODEJS_16_X,
    "nodejs18.x": CDKRuntime.NODEJS_18_X,
    "nodejs20.x": CDKRuntime.NODEJS_20_X,
    "nodejs22.x": CDKRuntime.NODEJS_22_X,
    "python3.7": CDKRuntime.PYTHON_3_7,
    "python3.8": CDKRuntime.PYTHON_3_8,
    "python3.9": CDKRuntime.PYTHON_3_9,
    "python3.10": CDKRuntime.PYTHON_3_10,
    "python3.11": CDKRuntime.PYTHON_3_11,
    "python3.12": CDKRuntime.PYTHON_3_12,
    "dotnetcore3.1": CDKRuntime.DOTNET_CORE_3_1,
    dotnet6: CDKRuntime.DOTNET_6,
    dotnet8: CDKRuntime.DOTNET_8,
    java8: CDKRuntime.JAVA_8,
    java11: CDKRuntime.JAVA_11,
    java17: CDKRuntime.JAVA_17,
    java21: CDKRuntime.JAVA_21,
    "go1.x": CDKRuntime.PROVIDED_AL2023,
    go: CDKRuntime.PROVIDED_AL2023,
};
/**
 * The `Function` construct is a higher level CDK construct that makes it easy to create a Lambda Function with support for Live Lambda Development.
 *
 * @example
 *
 * ```js
 * import { Function } from "sst/constructs";
 *
 * new Function(stack, "MySnsLambda", {
 *   handler: "src/sns/index.main",
 * });
 * ```
 */
export class Function extends CDKFunction {
    id;
    _isLiveDevEnabled;
    /** @internal */
    _doNotAllowOthersToBind;
    /** @internal */
    _overrideMetadataHandler;
    missingSourcemap;
    functionUrl;
    props;
    allBindings = [];
    constructor(scope, id, props) {
        const app = scope.node.root;
        const stack = Stack.of(scope);
        // Merge with app defaultFunctionProps
        // note: reverse order so later prop override earlier ones
        stack.defaultFunctionProps
            .slice()
            .reverse()
            .forEach((per) => {
            props = Function.mergeProps(per, props);
        });
        props.runtime = props.runtime || "nodejs22.x";
        if (props.runtime === "go1.x")
            useWarning().add("go.deprecated");
        // Set defaults
        const functionName = props.functionName &&
            (typeof props.functionName === "string"
                ? props.functionName
                : props.functionName({ stack, functionProps: props }));
        const timeout = Function.normalizeTimeout(props.timeout);
        const architecture = (() => {
            if (props.architecture === "arm_64")
                return Architecture.ARM_64;
            if (props.architecture === "x86_64")
                return Architecture.X86_64;
            return Architecture.X86_64;
        })();
        const memorySize = Function.normalizeMemorySize(props.memorySize);
        const diskSize = Function.normalizeDiskSize(props.diskSize);
        const tracing = Tracing[(props.tracing || "active").toUpperCase()];
        const logRetention = props.logRetention &&
            RetentionDays[props.logRetention.toUpperCase()];
        const isLiveDevEnabled = app.mode === "dev" && (props.enableLiveDev === false ? false : true);
        Function.validateHandlerSet(id, props);
        Function.validateVpcSettings(id, props);
        // Handle inactive stacks
        if (!stack.isActive) {
            // Note: need to override runtime as CDK does not support inline code
            //       for some runtimes.
            super(scope, id, {
                ...props,
                architecture,
                code: Code.fromInline("export function placeholder() {}"),
                handler: "index.placeholder",
                functionName,
                runtime: CDKRuntime.NODEJS_22_X,
                memorySize,
                ephemeralStorageSize: diskSize,
                timeout,
                tracing,
                environment: props.environment,
                layers: Function.buildLayers(scope, id, props),
                logRetention,
                logRetentionRetryOptions: logRetention && { maxRetries: 100 },
            });
        }
        // Handle local development (ie. sst start)
        // - set runtime to nodejs for non-Node runtimes (b/c the stub is in Node)
        // - set retry to 0. When the debugger is disconnected, the Cron construct
        //   will still try to periodically invoke the Lambda, and the requests would
        //   fail and retry. So when launching `sst start`, a couple of retry requests
        //   from recent failed request will be received. And this behavior is confusing.
        else if (isLiveDevEnabled) {
            // If debugIncreaseTimeout is enabled:
            //   set timeout to 900s. This will give people more time to debug the function
            //   without timing out the request. Note API Gateway requests have a maximum
            //   timeout of 29s. In this case, the API will timeout, but the Lambda function
            //   will continue to run.
            let debugOverrideProps;
            if (app.debugIncreaseTimeout) {
                debugOverrideProps = {
                    timeout: toCdkDuration("900 second"),
                };
            }
            // Ensure descriptions fits the 256 chars limit
            const description = props.description
                ? `${props.description.substring(0, 240)} (live)`
                : `live`;
            super(scope, id, {
                ...props,
                ...(props.runtime === "container"
                    ? {
                        description,
                        code: Code.fromAssetImage(path.resolve(__dirname, "../support/bridge"), {
                            ...(architecture?.dockerPlatform
                                ? { platform: Platform.custom(architecture.dockerPlatform) }
                                : {}),
                        }),
                        handler: CDKHandler.FROM_IMAGE,
                        runtime: CDKRuntime.FROM_IMAGE,
                        layers: undefined,
                    }
                    : {
                        description,
                        runtime: CDKRuntime.NODEJS_22_X,
                        code: Code.fromAsset(path.resolve(__dirname, "../support/bridge")),
                        handler: "live-lambda.handler",
                        layers: [],
                    }),
                architecture,
                functionName,
                memorySize,
                ephemeralStorageSize: diskSize,
                timeout,
                tracing,
                environment: props.environment,
                logRetention,
                logRetentionRetryOptions: logRetention && { maxRetries: 100 },
                retryAttempts: 0,
                ...(debugOverrideProps || {}),
            });
            this.addEnvironment("SST_FUNCTION_ID", this.node.addr);
            useDeferredTasks().add(async () => {
                if (app.isRunningSSTTest())
                    return;
                const bootstrap = await useBootstrap();
                const bootstrapBucketArn = `arn:${Stack.of(this).partition}:s3:::${bootstrap.bucket}`;
                this.attachPermissions([
                    new PolicyStatement({
                        actions: ["iot:*"],
                        effect: Effect.ALLOW,
                        resources: ["*"],
                    }),
                    new PolicyStatement({
                        actions: ["s3:*"],
                        effect: Effect.ALLOW,
                        resources: [bootstrapBucketArn, `${bootstrapBucketArn}/*`],
                    }),
                ]);
            });
        }
        // Handle build
        else {
            super(scope, id, {
                ...props,
                ...(props.runtime === "container"
                    ? {
                        code: Code.fromInline("export function placeholder() {}"),
                        handler: "index.placeholder",
                        runtime: CDKRuntime.NODEJS_22_X,
                        layers: undefined,
                    }
                    : {
                        code: Code.fromInline("export function placeholder() {}"),
                        handler: "index.placeholder",
                        runtime: CDKRuntime.NODEJS_22_X,
                        layers: Function.buildLayers(scope, id, props),
                    }),
                architecture,
                functionName,
                memorySize,
                ephemeralStorageSize: diskSize,
                timeout,
                tracing,
                environment: props.environment,
                logRetention,
                logRetentionRetryOptions: logRetention && { maxRetries: 100 },
            });
            useDeferredTasks().add(async () => {
                if (props.runtime === "container")
                    Colors.line(`➜  Building the container image for the "${this.node.id}" function...`);
                // Build function
                const result = await useRuntimeHandlers().build(this.node.addr, "deploy");
                if (result.type === "error") {
                    throw new VisibleError([
                        `Failed to build function "${props.handler}"`,
                        ...result.errors,
                    ].join("\n"));
                }
                // Update function code for container
                const cfnFunction = this.node.defaultChild;
                if (props.runtime === "container") {
                    const code = Code.fromAssetImage(props.handler, {
                        ...(architecture?.dockerPlatform
                            ? { platform: Platform.custom(architecture.dockerPlatform) }
                            : {}),
                        ...(props.container?.cmd ? { cmd: props.container.cmd } : {}),
                        ...(props.container?.file ? { file: props.container.file } : {}),
                        ...(props.container?.buildArgs
                            ? { buildArgs: props.container.buildArgs }
                            : {}),
                        ...(props.container?.buildSsh
                            ? { buildSsh: props.container.buildSsh }
                            : {}),
                        ...(props.container?.cacheFrom
                            ? { cacheFrom: props.container.cacheFrom }
                            : {}),
                        ...(props.container?.cacheTo
                            ? { cacheTo: props.container.cacheTo }
                            : {}),
                        exclude: [".sst/dist", ".sst/artifacts"],
                        ignoreMode: IgnoreMode.GLOB,
                    });
                    const codeConfig = code.bind(this);
                    cfnFunction.packageType = "Image";
                    cfnFunction.code = {
                        imageUri: codeConfig.image?.imageUri,
                    };
                    delete cfnFunction.runtime;
                    delete cfnFunction.handler;
                    code.bindToResource(cfnFunction);
                    return;
                }
                // Update function code for non-container
                if (result.sourcemap) {
                    const data = await fs.readFile(result.sourcemap);
                    await fs.writeFile(result.sourcemap, zlib.gzipSync(data));
                    const asset = new Asset(this, this.id + "-Sourcemap", {
                        path: result.sourcemap,
                    });
                    await fs.rm(result.sourcemap);
                    useFunctions().sourcemaps.add(stack.stackName, {
                        asset,
                        tarKey: this.functionArn,
                    });
                }
                this.missingSourcemap = !result.sourcemap;
                // Update code
                const code = AssetCode.fromAsset(result.out);
                const codeConfig = code.bind(this);
                cfnFunction.code = {
                    s3Bucket: codeConfig.s3Location?.bucketName,
                    s3Key: codeConfig.s3Location?.objectKey,
                    s3ObjectVersion: codeConfig.s3Location?.objectVersion,
                };
                cfnFunction.handler = result.handler;
                code.bindToResource(cfnFunction);
                // Update runtime
                // @ts-ignore - override "runtime" private property
                this.runtime =
                    supportedRuntimes[props.runtime];
                cfnFunction.runtime = this.runtime.toString();
                if (props.runtime?.startsWith("java") &&
                    props.java?.experimentalUseProvidedRuntime) {
                    cfnFunction.runtime = props.java?.experimentalUseProvidedRuntime;
                }
            });
        }
        this.id = id;
        this._doNotAllowOthersToBind = props._doNotAllowOthersToBind;
        this.props = props || {};
        if (this.isNodeRuntime()) {
            // Enable reusing connections with Keep-Alive for NodeJs
            // Lambda function
            this.addEnvironment("AWS_NODEJS_CONNECTION_REUSE_ENABLED", "1", {
                removeInEdge: true,
            });
        }
        this.attachPermissions(props.permissions || []);
        // Add config
        this.addEnvironment("SST_APP", app.name, { removeInEdge: true });
        this.addEnvironment("SST_STAGE", app.stage, { removeInEdge: true });
        this.addEnvironment("SST_SSM_PREFIX", useProject().config.ssmPrefix, {
            removeInEdge: true,
        });
        this.bind(props.bind || []);
        this.disableCloudWatchLogs();
        this.createUrl();
        this.createSecretPrefetcher();
        this._isLiveDevEnabled = isLiveDevEnabled;
        useFunctions().add(this.node.addr, props);
        app.registerTypes(this);
    }
    /**
     * The AWS generated URL of the Function.
     */
    get url() {
        return this.functionUrl?.url;
    }
    /**
     * Binds additional resources to function.
     *
     * @example
     * ```js
     * fn.bind([STRIPE_KEY, bucket]);
     * ```
     */
    bind(constructs) {
        // Get referenced secrets
        const referencedSecrets = [];
        constructs.forEach((r) => referencedSecrets.push(...getBindingReferencedSecrets(r)));
        [...constructs, ...referencedSecrets].forEach((r) => {
            // Bind environment
            const env = getBindingEnvironments(r);
            Object.entries(env).forEach(([key, value]) => this.addEnvironment(key, value));
            // Bind permissions
            const policyStatements = getBindingPermissions(r);
            this.attachPermissions(policyStatements);
        });
        this.allBindings.push(...constructs, ...referencedSecrets);
    }
    /**
     * Attaches additional permissions to function.
     *
     * @example
     * ```js {20}
     * fn.attachPermissions(["s3"]);
     * ```
     */
    attachPermissions(permissions) {
        // Grant IAM permissions
        if (this.role) {
            attachPermissionsToRole(this.role, permissions);
        }
        // Add config
        if (permissions !== "*") {
            permissions
                .filter((p) => p instanceof Job)
                .forEach((p) => this.bind([p]));
        }
    }
    /** @internal */
    getConstructMetadata() {
        return {
            type: "Function",
            data: {
                arn: this.functionArn,
                runtime: this.props.runtime,
                handler: this._overrideMetadataHandler ?? this.props.handler,
                missingSourcemap: this.missingSourcemap === true ? true : undefined,
                localId: this.node.addr,
                secrets: this.allBindings
                    .map((r) => (isSSTConstruct(r) ? r : r.resource))
                    .filter((r) => r instanceof Secret)
                    .map((c) => c.name),
                prefetchSecrets: this.props.prefetchSecrets,
            },
        };
    }
    /** @internal */
    getBindings() {
        return {
            clientPackage: "function",
            variables: {
                functionName: {
                    type: "plain",
                    value: this.functionName,
                },
            },
            permissions: {
                "lambda:*": [this.functionArn],
            },
        };
    }
    createUrl() {
        const { url } = this.props;
        if (url === false || url === undefined) {
            return;
        }
        let authType;
        let cors;
        let streaming;
        if (url === true) {
            authType = FunctionUrlAuthType.NONE;
            cors = true;
            streaming = false;
        }
        else {
            authType =
                url.authorizer === "iam"
                    ? FunctionUrlAuthType.AWS_IAM
                    : FunctionUrlAuthType.NONE;
            cors = url.cors === undefined ? true : url.cors;
            streaming = url.streaming;
        }
        this.functionUrl = this.addFunctionUrl({
            authType,
            cors: functionUrlCors.buildCorsConfig(cors),
            invokeMode: streaming ? InvokeMode.RESPONSE_STREAM : InvokeMode.BUFFERED,
        });
    }
    createSecretPrefetcher() {
        const { prefetchSecrets } = this.props;
        if (!prefetchSecrets)
            return;
        const stack = Stack.of(this);
        // Create custom resource to prewarm on deploy
        const policy = new Policy(this, "SecretPrefetcherPolicy", {
            statements: [
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ["lambda:GetFunction", "lambda:UpdateFunctionConfiguration"],
                    resources: [this.functionArn],
                }),
                new PolicyStatement({
                    effect: Effect.ALLOW,
                    actions: ["ssm:GetParameters"],
                    resources: [
                        `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter${Config.PREFIX.STAGE}*`,
                        `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter${Config.PREFIX.FALLBACK}*`,
                    ],
                }),
            ],
        });
        stack.customResourceHandler.role?.attachInlinePolicy(policy);
        const resource = new CustomResource(this, "SecretPrefetcher", {
            serviceToken: stack.customResourceHandler.functionArn,
            resourceType: "Custom::SecretPrefetcher",
            properties: {
                version: Date.now().toString(),
                functionName: this.functionName,
            },
        });
        resource.node.addDependency(policy);
    }
    disableCloudWatchLogs() {
        const disableCloudWatchLogs = this.props.disableCloudWatchLogs ?? false;
        if (!disableCloudWatchLogs)
            return;
        this.attachPermissions([
            new PolicyStatement({
                effect: Effect.DENY,
                actions: [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources: ["*"],
            }),
        ]);
    }
    isNodeRuntime() {
        const { runtime } = this.props;
        return runtime.startsWith("nodejs");
    }
    static validateHandlerSet(id, props) {
        if (!props.handler) {
            throw new Error(`No handler defined for the "${id}" Lambda function`);
        }
    }
    static validateVpcSettings(id, props) {
        if (props.securityGroups && !props.vpc) {
            throw new Error(`Cannot configure "securityGroups" without "vpc" for the "${id}" Lambda function.`);
        }
    }
    static buildLayers(scope, id, props) {
        return (props.layers || []).map((layer) => {
            if (typeof layer === "string") {
                return LayerVersion.fromLayerVersionArn(scope, `${id}${layer}`, layer);
            }
            return Function.handleImportedLayer(scope, layer);
        });
    }
    static normalizeMemorySize(memorySize) {
        if (typeof memorySize === "string") {
            return toCdkSize(memorySize).toMebibytes();
        }
        return memorySize || 1024;
    }
    static normalizeDiskSize(diskSize) {
        if (typeof diskSize === "string") {
            return toCdkSize(diskSize);
        }
        return CDKSize.mebibytes(diskSize || 512);
    }
    static normalizeTimeout(timeout) {
        if (typeof timeout === "string") {
            return toCdkDuration(timeout);
        }
        return CDKDuration.seconds(timeout || 10);
    }
    static handleImportedLayer(scope, layer) {
        const layerStack = Stack.of(layer);
        const currentStack = Stack.of(scope);
        // Use layer directly if:
        // - layer is created in the current stack; OR
        // - layer is imported (ie. layerArn is a string)
        if (layerStack === currentStack ||
            !Token.isUnresolved(layer.layerVersionArn)) {
            return layer;
        }
        // layer is created from another stack
        else {
            // set stack dependency b/c layerStack need to create the SSM first
            currentStack.addDependency(layerStack);
            // store layer ARN in SSM in layer's stack
            const parameterId = `${layer.node.id}Arn-${layer.node.addr}`;
            const parameterName = `/layers/${layerStack.node.id}/${parameterId}`;
            const existingSsmParam = layerStack.node.tryFindChild(parameterId);
            if (!existingSsmParam) {
                new StringParameter(layerStack, parameterId, {
                    parameterName,
                    stringValue: layer.layerVersionArn,
                });
            }
            // import layer from SSM value
            const layerId = `I${layer.node.id}-${layer.node.addr}`;
            const existingLayer = scope.node.tryFindChild(layerId);
            if (existingLayer) {
                return existingLayer;
            }
            else {
                return LayerVersion.fromLayerVersionArn(scope, layerId, StringParameter.valueForStringParameter(scope, parameterName));
            }
        }
    }
    static isInlineDefinition(definition) {
        return typeof definition === "string" || definition instanceof Function;
    }
    static fromDefinition(scope, id, definition, inheritedProps, inheritErrorMessage) {
        if (typeof definition === "string") {
            return new Function(scope, id, {
                ...(inheritedProps || {}),
                handler: definition,
                _doNotAllowOthersToBind: true,
            });
        }
        else if (definition instanceof Function) {
            if (inheritedProps && Object.keys(inheritedProps).length > 0) {
                throw new Error(inheritErrorMessage ||
                    `Cannot inherit default props when a Function is provided`);
            }
            return definition;
        }
        else if (definition instanceof CDKFunction) {
            throw new Error(`Please use sst.Function instead of lambda.Function for the "${id}" Function.`);
        }
        else if (definition.handler !== undefined) {
            return new Function(scope, id, {
                ...Function.mergeProps(inheritedProps, definition),
                _doNotAllowOthersToBind: true,
            });
        }
        throw new Error(`Invalid function definition for the "${id}" Function`);
    }
    static mergeProps(baseProps, props) {
        // Merge environment
        const environment = {
            ...(baseProps?.environment || {}),
            ...(props?.environment || {}),
        };
        const environmentProp = Object.keys(environment).length === 0 ? {} : { environment };
        // Merge layers
        const layers = [...(baseProps?.layers || []), ...(props?.layers || [])];
        const layersProp = layers.length === 0 ? {} : { layers };
        // Merge bind
        const bind = [...(baseProps?.bind || []), ...(props?.bind || [])];
        const bindProp = bind.length === 0 ? {} : { bind };
        // Merge permissions
        let permissionsProp;
        if (baseProps?.permissions === "*") {
            permissionsProp = { permissions: baseProps.permissions };
        }
        else if (props?.permissions === "*") {
            permissionsProp = { permissions: props.permissions };
        }
        else {
            const permissions = (baseProps?.permissions || []).concat(props?.permissions || []);
            permissionsProp = permissions.length === 0 ? {} : { permissions };
        }
        return {
            ...(baseProps || {}),
            ...(props || {}),
            ...bindProp,
            ...layersProp,
            ...environmentProp,
            ...permissionsProp,
        };
    }
}
export const useFunctions = createAppContext(() => {
    const functions = {};
    const sourcemaps = {};
    return {
        sourcemaps: {
            add(stack, source) {
                let arr = sourcemaps[stack];
                if (!arr)
                    sourcemaps[stack] = arr = [];
                arr.push(source);
            },
            forStack(stack) {
                return (sourcemaps[stack] || []).sort((a, b) => {
                    if (a.asset.node.path > b.asset.node.path)
                        return 1;
                    if (a.asset.node.path < b.asset.node.path)
                        return -1;
                    return 0;
                });
            },
        },
        fromID(id) {
            const result = functions[id];
            if (!result)
                return;
            return result;
        },
        add(name, props) {
            functions[name] = props;
        },
        get all() {
            return functions;
        },
    };
});
