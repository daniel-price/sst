import fs from "fs";
import path from "path";
import crypto from "crypto";
import { Duration as CdkDuration, RemovalPolicy, CustomResource, Fn, } from "aws-cdk-lib/core";
import { Code, Runtime, Function as CdkFunction, Architecture, } from "aws-cdk-lib/aws-lambda";
import { AttributeType, Billing, TableV2 as Table, } from "aws-cdk-lib/aws-dynamodb";
import { Provider } from "aws-cdk-lib/custom-resources";
import { Queue } from "aws-cdk-lib/aws-sqs";
import { SqsEventSource } from "aws-cdk-lib/aws-lambda-event-sources";
import { Stack } from "./Stack.js";
import { SsrSite, } from "./SsrSite.js";
import { compareSemver } from "./util/compareSemver.js";
import { toCdkSize } from "./util/size.js";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";
import { RetentionDays } from "aws-cdk-lib/aws-logs";
import { VisibleError } from "../error.js";
import { Logger } from "../logger.js";
const DEFAULT_OPEN_NEXT_VERSION = "3.2.2";
/**
 * The `NextjsSite` construct is a higher level CDK construct that makes it easy to create a Next.js app.
 * @example
 * Deploys a Next.js app in the `my-next-app` directory.
 *
 * ```js
 * new NextjsSite(stack, "web", {
 *   path: "my-next-app/",
 * });
 * ```
 */
export class NextjsSite extends SsrSite {
    _routes;
    routesManifest;
    appPathRoutesManifest;
    appPathsManifest;
    pagesManifest;
    prerenderManifest;
    openNextOutput;
    constructor(scope, id, props = {}) {
        const openNextVersion = props.openNextVersion ?? DEFAULT_OPEN_NEXT_VERSION;
        super(scope, id, {
            buildCommand: [
                "npx",
                "--yes",
                `${compareSemver(openNextVersion, "3.1.3") <= 0
                    ? "open-next"
                    : "@opennextjs/aws"}@${openNextVersion}`,
                "build",
            ].join(" "),
            ...props,
        });
        const disableIncrementalCache = this.openNextOutput?.additionalProps?.disableIncrementalCache ?? false;
        const disableTagCache = this.openNextOutput?.additionalProps?.disableTagCache ?? false;
        this.handleMissingSourcemap();
        if (this.openNextOutput?.edgeFunctions?.middleware) {
            this.setMiddlewareEnv();
        }
        if (!disableIncrementalCache) {
            this.createRevalidationQueue();
            if (!disableTagCache) {
                this.createRevalidationTable();
            }
        }
    }
    createFunctionOrigin(fn, key, bucket) {
        const { path: sitePath, environment, cdk } = this.props;
        const baseServerConfig = {
            description: "Next.js Server",
            environment: {
                CACHE_BUCKET_NAME: bucket.bucketName,
                CACHE_BUCKET_KEY_PREFIX: "_cache",
                CACHE_BUCKET_REGION: Stack.of(this).region,
            },
        };
        return {
            type: "function",
            constructId: `${key}ServerFunction`,
            function: {
                ...baseServerConfig,
                handler: fn.handler,
                bundle: path.join(sitePath, fn.bundle),
                runtime: this.props.runtime ?? "nodejs18.x",
                architecture: Architecture.ARM_64,
                memorySize: this.props.memorySize ?? 1536,
                environment: {
                    ...environment,
                    ...baseServerConfig.environment,
                },
            },
            streaming: fn.streaming,
            injections: [],
        };
    }
    createEcsOrigin(ecs, key, bucket) {
        throw new Error("Ecs origin are not supported yet");
    }
    createEdgeOrigin(fn, key, bucket) {
        const { path: sitePath, cdk, environment } = this.props;
        const baseServerConfig = {
            environment: {
                CACHE_BUCKET_NAME: bucket.bucketName,
                CACHE_BUCKET_KEY_PREFIX: "_cache",
                CACHE_BUCKET_REGION: Stack.of(this).region,
            },
        };
        return {
            constructId: `${key}EdgeFunction`,
            function: {
                handler: fn.handler,
                bundle: path.join(sitePath, fn.bundle),
                runtime: "nodejs18.x",
                memorySize: 1024,
                environment: {
                    ...environment,
                    ...baseServerConfig.environment,
                },
            },
        };
    }
    plan(bucket) {
        const { path: sitePath } = this.props;
        const imageOptimization = this.props.imageOptimization;
        const openNextOutputPath = path.join(sitePath ?? ".", ".open-next", "open-next.output.json");
        if (!fs.existsSync(openNextOutputPath)) {
            throw new VisibleError(`Failed to load ".open-next/output.json" for the "${this.id}" site.`);
        }
        const openNextOutput = JSON.parse(fs.readFileSync(openNextOutputPath).toString());
        this.openNextOutput = openNextOutput;
        const imageOpt = openNextOutput.origins
            .imageOptimizer;
        const defaultOrigin = openNextOutput.origins.default;
        const remainingOrigins = Object.entries(openNextOutput.origins).filter(([key, value]) => {
            const result = key !== "imageOptimizer" && key !== "default" && key !== "s3";
            return result;
        });
        const edgeFunctions = Object.entries(openNextOutput.edgeFunctions).reduce((acc, [key, value]) => {
            return { ...acc, [key]: this.createEdgeOrigin(value, key, bucket) };
        }, {});
        return this.validatePlan({
            edge: false,
            cloudFrontFunctions: {
                serverCfFunction: {
                    constructId: "CloudFrontFunction",
                    injections: [
                        this.useCloudFrontFunctionHostHeaderInjection(),
                        this.useCloudFrontFunctionCacheHeaderKey(),
                        this.useCloudfrontGeoHeadersInjection(),
                    ],
                },
            },
            edgeFunctions,
            origins: {
                s3: openNextOutput.origins.s3,
                imageOptimizer: {
                    type: "image-optimization-function",
                    function: {
                        description: "Next.js Image Optimization Function",
                        handler: imageOpt.handler,
                        code: Code.fromAsset(path.join(sitePath, imageOpt.bundle)),
                        runtime: Runtime.NODEJS_22_X,
                        architecture: Architecture.ARM_64,
                        environment: {
                            BUCKET_NAME: bucket.bucketName,
                            BUCKET_KEY_PREFIX: "_assets",
                            ...(this.props.imageOptimization?.staticImageOptimization
                                ? { OPENNEXT_STATIC_ETAG: "true" }
                                : {}),
                        },
                        permissions: ["s3"],
                        memorySize: imageOptimization?.memorySize
                            ? typeof imageOptimization.memorySize === "string"
                                ? toCdkSize(imageOptimization.memorySize).toMebibytes()
                                : imageOptimization.memorySize
                            : 1536,
                    },
                },
                default: defaultOrigin.type === "ecs"
                    ? this.createEcsOrigin(defaultOrigin, "default", bucket)
                    : this.createFunctionOrigin(defaultOrigin, "default", bucket),
                ...Object.fromEntries(remainingOrigins.map(([key, value]) => [
                    key,
                    value.type === "ecs"
                        ? this.createEcsOrigin(value, key, bucket)
                        : this.createFunctionOrigin(value, key, bucket),
                ])),
            },
            behaviors: openNextOutput.behaviors.map((behavior) => {
                return {
                    pattern: behavior.pattern === "*" ? undefined : behavior.pattern,
                    origin: behavior.origin,
                    cacheType: behavior.origin === "s3" ? "static" : "server",
                    cfFunction: "serverCfFunction",
                    edgeFunction: behavior.edgeFunction ?? "",
                };
            }),
            buildId: this.getBuildId(),
            warmer: openNextOutput.additionalProps?.warmer
                ? {
                    function: path.join(sitePath, openNextOutput.additionalProps.warmer.bundle),
                }
                : undefined,
            serverCachePolicy: {
                allowedHeaders: ["x-open-next-cache-key"],
            },
        });
    }
    setMiddlewareEnv() {
        const origins = this.serverFunctions.reduce((acc, server) => {
            return {
                ...acc,
                [server.function
                    ? server.id.replace("ServerFunction", "")
                    : server.id.replace("ServerContainer", "")]: {
                    host: Fn.parseDomainName(server.url ?? ""),
                    port: 443,
                    protocol: "https",
                },
            };
        }, {});
        this.edgeFunctions?.middleware?.addEnvironment("OPEN_NEXT_ORIGIN", Fn.toJsonString(origins));
    }
    createRevalidationQueue() {
        if (!this.serverFunction)
            return;
        const { cdk } = this.props;
        const queue = new Queue(this, "RevalidationQueue", {
            fifo: true,
            receiveMessageWaitTime: CdkDuration.seconds(20),
        });
        const consumer = new CdkFunction(this, "RevalidationFunction", {
            description: "Next.js revalidator",
            handler: "index.handler",
            code: Code.fromAsset(path.join(this.props.path, ".open-next", "revalidation-function")),
            runtime: Runtime.NODEJS_22_X,
            timeout: CdkDuration.seconds(30),
            ...cdk?.revalidation,
        });
        consumer.addEventSource(new SqsEventSource(queue, { batchSize: 5 }));
        this.serverFunctions.forEach((server) => {
            // Allow server to send messages to the queue
            server.addEnvironment("REVALIDATION_QUEUE_URL", queue.queueUrl);
            server.addEnvironment("REVALIDATION_QUEUE_REGION", Stack.of(this).region);
            queue.grantSendMessages(server.role);
        });
    }
    createRevalidationTable() {
        if (!this.serverFunction)
            return;
        const { path: sitePath } = this.props;
        const table = new Table(this, "RevalidationTable", {
            partitionKey: { name: "tag", type: AttributeType.STRING },
            sortKey: { name: "path", type: AttributeType.STRING },
            pointInTimeRecovery: true,
            billing: Billing.onDemand(),
            globalSecondaryIndexes: [
                {
                    indexName: "revalidate",
                    partitionKey: { name: "path", type: AttributeType.STRING },
                    sortKey: { name: "revalidatedAt", type: AttributeType.NUMBER },
                },
            ],
            removalPolicy: RemovalPolicy.DESTROY,
        });
        this.serverFunctions.forEach((server) => {
            server?.addEnvironment("CACHE_DYNAMO_TABLE", table.tableName);
            table.grantReadWriteData(server.role);
        });
        const dynamodbProviderPath = path.join(sitePath, ".open-next", "dynamodb-provider");
        if (fs.existsSync(dynamodbProviderPath)) {
            // Provision 128MB of memory for every 4,000 prerendered routes,
            // 1GB per 40,000, up to 10GB. This tends to use ~70% of the memory
            // provisioned when testing.
            const prerenderedRouteCount = Object.keys(this.usePrerenderManifest()?.routes ?? {}).length;
            const insertFn = new CdkFunction(this, "RevalidationInsertFunction", {
                description: "Next.js revalidation data insert",
                handler: "index.handler",
                code: Code.fromAsset(dynamodbProviderPath),
                runtime: Runtime.NODEJS_22_X,
                timeout: CdkDuration.minutes(15),
                memorySize: Math.min(10240, Math.max(128, Math.ceil(prerenderedRouteCount / 4000) * 128)),
                initialPolicy: [
                    new PolicyStatement({
                        actions: [
                            "dynamodb:BatchWriteItem",
                            "dynamodb:PutItem",
                            "dynamodb:DescribeTable",
                        ],
                        resources: [table.tableArn],
                    }),
                ],
                environment: {
                    CACHE_DYNAMO_TABLE: table.tableName,
                },
            });
            const provider = new Provider(this, "RevalidationProvider", {
                onEventHandler: insertFn,
                logRetention: RetentionDays.ONE_DAY,
            });
            new CustomResource(this, "RevalidationResource", {
                serviceToken: provider.serviceToken,
                properties: {
                    version: Date.now().toString(),
                },
            });
        }
    }
    getConstructMetadata() {
        return {
            type: "NextjsSite",
            ...this.getConstructMetadataBase(),
        };
    }
    useRoutes() {
        if (this._routes)
            return this._routes;
        const routesManifest = this.useRoutesManifest();
        const appPathRoutesManifest = this.useAppPathRoutesManifest();
        const dynamicAndStaticRoutes = [
            ...routesManifest.dynamicRoutes,
            ...routesManifest.staticRoutes,
        ].map(({ page, regex }) => {
            const cwRoute = NextjsSite.buildCloudWatchRouteName(page);
            const cwHash = NextjsSite.buildCloudWatchRouteHash(page);
            const sourcemapPath = this.getSourcemapForAppRoute(page) ||
                this.getSourcemapForPagesRoute(page);
            return {
                route: page,
                regexMatch: regex,
                logGroupPath: `/${cwHash}${cwRoute}`,
                sourcemapPath: sourcemapPath,
                sourcemapKey: cwHash,
            };
        });
        // Some app routes are not in the routes manifest, so we need to add them
        // ie. app/api/route.ts => IS NOT in the routes manifest
        //     app/items/[slug]/route.ts => IS in the routes manifest (dynamicRoutes)
        const appRoutes = Object.values(appPathRoutesManifest)
            .filter((page) => routesManifest.dynamicRoutes.every((route) => route.page !== page) &&
            routesManifest.staticRoutes.every((route) => route.page !== page))
            .map((page) => {
            const cwRoute = NextjsSite.buildCloudWatchRouteName(page);
            const cwHash = NextjsSite.buildCloudWatchRouteHash(page);
            const sourcemapPath = this.getSourcemapForAppRoute(page);
            return {
                route: page,
                prefixMatch: page,
                logGroupPath: `/${cwHash}${cwRoute}`,
                sourcemapPath: sourcemapPath,
                sourcemapKey: cwHash,
            };
        });
        const dataRoutes = (routesManifest.dataRoutes || []).map(({ page, dataRouteRegex }) => {
            const routeDisplayName = page.endsWith("/")
                ? `/_next/data/BUILD_ID${page}index.json`
                : `/_next/data/BUILD_ID${page}.json`;
            const cwRoute = NextjsSite.buildCloudWatchRouteName(routeDisplayName);
            const cwHash = NextjsSite.buildCloudWatchRouteHash(page);
            return {
                route: routeDisplayName,
                regexMatch: dataRouteRegex,
                logGroupPath: `/${cwHash}${cwRoute}`,
            };
        });
        this._routes = [
            ...[...dynamicAndStaticRoutes, ...appRoutes].sort((a, b) => a.route.localeCompare(b.route)),
            ...dataRoutes.sort((a, b) => a.route.localeCompare(b.route)),
        ];
        return this._routes;
    }
    useRoutesManifest() {
        if (this.routesManifest)
            return this.routesManifest;
        const { path: sitePath } = this.props;
        const id = this.node.id;
        try {
            const content = fs
                .readFileSync(path.join(sitePath, ".next/routes-manifest.json"))
                .toString();
            this.routesManifest = JSON.parse(content);
            return this.routesManifest;
        }
        catch (e) {
            console.error(e);
            throw new VisibleError(`Failed to read routes data from ".next/routes-manifest.json" for the "${id}" site.`);
        }
    }
    useAppPathRoutesManifest() {
        // Example
        // {
        //   "/_not-found": "/_not-found",
        //   "/page": "/",
        //   "/favicon.ico/route": "/favicon.ico",
        //   "/api/route": "/api",                    <- app/api/route.js
        //   "/api/sub/route": "/api/sub",            <- app/api/sub/route.js
        //   "/items/[slug]/route": "/items/[slug]"   <- app/items/[slug]/route.js
        // }
        if (this.appPathRoutesManifest)
            return this.appPathRoutesManifest;
        const { path: sitePath } = this.props;
        try {
            const content = fs
                .readFileSync(path.join(sitePath, ".next/app-path-routes-manifest.json"))
                .toString();
            this.appPathRoutesManifest = JSON.parse(content);
            return this.appPathRoutesManifest;
        }
        catch (e) {
            return {};
        }
    }
    useAppPathsManifest() {
        if (this.appPathsManifest)
            return this.appPathsManifest;
        const { path: sitePath } = this.props;
        try {
            const content = fs
                .readFileSync(path.join(sitePath, ".next/server/app-paths-manifest.json"))
                .toString();
            this.appPathsManifest = JSON.parse(content);
            return this.appPathsManifest;
        }
        catch (e) {
            return {};
        }
    }
    usePagesManifest() {
        if (this.pagesManifest)
            return this.pagesManifest;
        const { path: sitePath } = this.props;
        try {
            const content = fs
                .readFileSync(path.join(sitePath, ".next/server/pages-manifest.json"))
                .toString();
            this.pagesManifest = JSON.parse(content);
            return this.pagesManifest;
        }
        catch (e) {
            return {};
        }
    }
    usePrerenderManifest() {
        if (this.prerenderManifest)
            return this.prerenderManifest;
        const { path: sitePath } = this.props;
        try {
            const content = fs
                .readFileSync(path.join(sitePath, ".next/prerender-manifest.json"))
                .toString();
            this.prerenderManifest = JSON.parse(content);
            return this.prerenderManifest;
        }
        catch (e) {
            Logger.debug("Failed to load prerender-manifest.json", e);
        }
    }
    // This function is used to improve cache hit ratio by setting the cache key based on the request headers and the path
    // next/image only need the accept header, and this header is not useful for the rest of the query
    useCloudFrontFunctionCacheHeaderKey() {
        return `
function getHeader(key) {
  var header = request.headers[key];
  if(header) {
      if(header.multiValue){
          return header.multiValue.map((header) => header.value).join(",");
      }
      if(header.value){
          return header.value;
      }
  }
  return ""
  }
  var cacheKey = "";
  if(request.uri.startsWith("/_next/image")) {
    cacheKey = getHeader("accept");
  }else {
    cacheKey = getHeader("rsc") + getHeader("next-router-prefetch") + getHeader("next-router-state-tree") + getHeader("next-url") + getHeader("x-prerender-revalidate");
  }
  if(request.cookies["__prerender_bypass"]) {
    cacheKey += request.cookies["__prerender_bypass"] ? request.cookies["__prerender_bypass"].value : "";
  }
  var crypto = require('crypto');
  
  var hashedKey = crypto.createHash('md5').update(cacheKey).digest('hex');
  request.headers["x-open-next-cache-key"] = {value: hashedKey};
  `;
    }
    // Inject the CloudFront viewer country, region, latitude, and longitude headers into the request headers
    // for OpenNext to use them
    useCloudfrontGeoHeadersInjection() {
        return `
if(request.headers["cloudfront-viewer-city"]) {
  request.headers["x-open-next-city"] = request.headers["cloudfront-viewer-city"];
}
if(request.headers["cloudfront-viewer-country"]) {
  request.headers["x-open-next-country"] = request.headers["cloudfront-viewer-country"];
}
if(request.headers["cloudfront-viewer-region"]) {
  request.headers["x-open-next-region"] = request.headers["cloudfront-viewer-region"];
}
if(request.headers["cloudfront-viewer-latitude"]) {
  request.headers["x-open-next-latitude"] = request.headers["cloudfront-viewer-latitude"];
}
if(request.headers["cloudfront-viewer-longitude"]) {
  request.headers["x-open-next-longitude"] = request.headers["cloudfront-viewer-longitude"];
}
    `;
    }
    getBuildId() {
        const { path: sitePath } = this.props;
        return fs.readFileSync(path.join(sitePath, ".next/BUILD_ID")).toString();
    }
    getSourcemapForAppRoute(page) {
        const { path: sitePath } = this.props;
        // Step 1: look up in "appPathRoutesManifest" to find the key with
        //         value equal to the page
        // {
        //   "/_not-found": "/_not-found",
        //   "/about/page": "/about",
        //   "/about/profile/page": "/about/profile",
        //   "/page": "/",
        //   "/favicon.ico/route": "/favicon.ico"
        // }
        const appPathRoutesManifest = this.useAppPathRoutesManifest();
        const appPathRoute = Object.keys(appPathRoutesManifest).find((key) => appPathRoutesManifest[key] === page);
        if (!appPathRoute)
            return;
        // Step 2: look up in "appPathsManifest" to find the file with key equal
        //         to the page
        // {
        //   "/_not-found": "app/_not-found.js",
        //   "/about/page": "app/about/page.js",
        //   "/about/profile/page": "app/about/profile/page.js",
        //   "/page": "app/page.js",
        //   "/favicon.ico/route": "app/favicon.ico/route.js"
        // }
        const appPathsManifest = this.useAppPathsManifest();
        const filePath = appPathsManifest[appPathRoute];
        if (!filePath)
            return;
        // Step 3: check the .map file exists
        const sourcemapPath = path.join(sitePath, ".next", "server", `${filePath}.map`);
        if (!fs.existsSync(sourcemapPath))
            return;
        return sourcemapPath;
    }
    getSourcemapForPagesRoute(page) {
        const { path: sitePath } = this.props;
        // Step 1: look up in "pathsManifest" to find the file with key equal
        //         to the page
        // {
        //   "/_app": "pages/_app.js",
        //   "/_error": "pages/_error.js",
        //   "/404": "pages/404.html",
        //   "/api/hello": "pages/api/hello.js",
        //   "/api/auth/[...nextauth]": "pages/api/auth/[...nextauth].js",
        //   "/api/next-auth-restricted": "pages/api/next-auth-restricted.js",
        //   "/": "pages/index.js",
        //   "/ssr": "pages/ssr.js"
        // }
        const pagesManifest = this.usePagesManifest();
        const filePath = pagesManifest[page];
        if (!filePath)
            return;
        // Step 2: check the .map file exists
        const sourcemapPath = path.join(sitePath, ".next", "server", `${filePath}.map`);
        if (!fs.existsSync(sourcemapPath))
            return;
        return sourcemapPath;
    }
    handleMissingSourcemap() {
        if (this.doNotDeploy || this.props.edge)
            return;
        const hasMissingSourcemap = this.useRoutes().every(({ sourcemapPath, sourcemapKey }) => !sourcemapPath || !sourcemapKey);
        if (!hasMissingSourcemap)
            return;
        this.serverFunction._overrideMissingSourcemap();
    }
    static buildCloudWatchRouteName(route) {
        return route.replace(/[^a-zA-Z0-9_\-/.#]/g, "");
    }
    static buildCloudWatchRouteHash(route) {
        const hash = crypto.createHash("sha256");
        hash.update(route);
        return hash.digest("hex").substring(0, 8);
    }
    static _test = {
        buildCloudWatchRouteName: NextjsSite.buildCloudWatchRouteName,
    };
}
