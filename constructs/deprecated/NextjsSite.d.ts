import { Construct } from "constructs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { SSTConstruct } from "../Construct.js";
import { DistributionDomainProps } from "../Distribution.js";
import { BaseSiteCdkDistributionProps } from "../BaseSite.js";
import { Permissions } from "../util/permission.js";
import { BindingProps } from "../util/binding.js";
export interface NextjsDomainProps extends DistributionDomainProps {
}
export interface NextjsCdkDistributionProps extends BaseSiteCdkDistributionProps {
}
export interface NextjsSiteProps {
    /**
     * Path to the directory where the website source is located.
     */
    path: string;
    /**
     * Path to the next executable, typically in node_modules.
     * This should be used if next is installed in a non-standard location.
     *
     * @default "./node_modules/.bin/next"
     */
    nextBinPath?: string;
    /**
     * The customDomain for this website. SST supports domains that are hosted either on [Route 53](https://aws.amazon.com/route53/) or externally.
     *
     * Note that you can also migrate externally hosted domains to Route 53 by [following this guide](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/MigratingDNS.html).
     *
     * @example
     * ```js {3}
     * new NextjsSite(stack, "Site", {
     *   path: "path/to/site",
     *   customDomain: "domain.com",
     * });
     * ```
     *
     * ```js {3-6}
     * new NextjsSite(stack, "Site", {
     *   path: "path/to/site",
     *   customDomain: {
     *     domainName: "domain.com",
     *     domainAlias: "www.domain.com",
     *     hostedZone: "domain.com"
     *   },
     * });
     * ```
     */
    customDomain?: string | NextjsDomainProps;
    /**
     * An object with the key being the environment variable name.
     *
     * @example
     * ```js {3-6}
     * new NextjsSite(stack, "NextSite", {
     *   path: "path/to/site",
     *   environment: {
     *     API_URL: api.url,
     *     USER_POOL_CLIENT: auth.cognitoUserPoolClient.userPoolClientId,
     *   },
     * });
     * ```
     */
    environment?: {
        [key: string]: string;
    };
    defaults?: {
        function?: {
            timeout?: number;
            memorySize?: number;
            permissions?: Permissions;
            /**
             * The runtime environment.
             * @default "nodejs18.x"
             * @example
             * ```js
             * new Function(stack, "Function", {
             *   path: "path/to/site",
             *   runtime: "nodejs18.x",
             * })
             *```
             */
            runtime?: "nodejs16.x" | "nodejs18.x" | "nodejs20.x" | "nodejs22.x";
        };
    };
    /**
     * When running `sst start`, a placeholder site is deployed. This is to ensure that the site content remains unchanged, and subsequent `sst start` can start up quickly.
     *
     * @example
     * ```js {3}
     * new NextjsSite(stack, "NextSite", {
     *   path: "path/to/site",
     *   disablePlaceholder: true,
     * });
     * ```
     */
    disablePlaceholder?: boolean;
    /**
     * While deploying, SST waits for the CloudFront cache invalidation process to finish. This ensures that the new content will be served once the deploy command finishes. However, this process can sometimes take more than 5 mins. For non-prod environments it might make sense to pass in `false`. That'll skip waiting for the cache to invalidate and speed up the deploy process.
     */
    waitForInvalidation?: boolean;
    commandHooks?: {
        /**
         * Commands to run after building the Next.js app. Commands are chained with `&&`, and they are run inside the Next.js app folder.
         *
         * @example
         * ```js
         * new NextjsSite(stack, "NextSite", {
         *   path: "path/to/site",
         *   commandHooks: {
         *     afterBuild: ["npx next-sitemap"],
         *   }
         * });
         * ```
         */
        afterBuild?: string[];
    };
    cdk?: {
        /**
         * Allows you to override default id for this construct.
         */
        id?: string;
        /**
         * Allows you to override default settings this construct uses internally to ceate the bucket
         */
        bucket?: s3.BucketProps | s3.IBucket;
        /**
         * Pass in a value to override the default settings this construct uses to create the CDK `Distribution` internally.
         */
        distribution?: NextjsCdkDistributionProps;
        /**
         * Override the default CloudFront cache policies created internally.
         */
        cachePolicies?: {
            staticCachePolicy?: cloudfront.ICachePolicy;
            imageCachePolicy?: cloudfront.ICachePolicy;
            lambdaCachePolicy?: cloudfront.ICachePolicy;
        };
        /**
         * Override the default CloudFront image origin request policy created internally
         */
        imageOriginRequestPolicy?: cloudfront.IOriginRequestPolicy;
        /**
         * Override the default settings this construct uses to create the CDK `Queue` internally.
         */
        regenerationQueue?: sqs.QueueProps;
    };
}
/**
 * The `NextjsSite` construct is a higher level CDK construct that makes it easy to create a Next.js app.
 *
 * @example
 *
 * Deploys a Next.js app in the `path/to/site` directory.
 *
 * ```js
 * new NextjsSite(stack, "NextSite", {
 *   path: "path/to/site",
 * });
 * ```
 */
export declare class NextjsSite extends Construct implements SSTConstruct {
    readonly id: string;
    /**
     * The default CloudFront cache policy properties for static pages.
     */
    static staticCachePolicyProps: cloudfront.CachePolicyProps;
    /**
     * The default CloudFront cache policy properties for images.
     */
    static imageCachePolicyProps: cloudfront.CachePolicyProps;
    /**
     * The default CloudFront cache policy properties for Lambda@Edge.
     */
    static lambdaCachePolicyProps: cloudfront.CachePolicyProps;
    /**
     * The default CloudFront image origin request policy properties for Lambda@Edge.
     */
    static imageOriginRequestPolicyProps: cloudfront.OriginRequestPolicyProps;
    readonly cdk: {
        /**
         * The internally created CDK `Bucket` instance.
         */
        bucket: s3.Bucket;
        /**
         * The internally created CDK `Queue` instance.
         */
        regenerationQueue: sqs.Queue;
        /**
         * The internally created CDK `Distribution` instance.
         */
        distribution: cloudfront.Distribution;
        /**
         * The Route 53 hosted zone for the custom domain.
         */
        hostedZone?: route53.IHostedZone;
        /**
         * The AWS Certificate Manager certificate for the custom domain.
         */
        certificate?: acm.ICertificate;
    };
    /**
     * The root SST directory used for builds.
     */
    private sstBuildDir;
    private props;
    private isPlaceholder;
    private buildOutDir;
    private assets;
    private awsCliLayer;
    private routesManifest;
    private edgeLambdaRole;
    private mainFunctionVersion;
    private apiFunctionVersion;
    private imageFunctionVersion;
    private regenerationFunction;
    constructor(scope: Construct, id: string, props: NextjsSiteProps);
    /**
     * The CloudFront URL of the website.
     */
    get url(): string;
    /**
     * If the custom domain is enabled, this is the URL of the website with the custom domain.
     */
    get customDomainUrl(): string | undefined;
    /**
     * The ARN of the internally created S3 Bucket.
     */
    get bucketArn(): string;
    /**
     * The name of the internally created S3 Bucket.
     */
    get bucketName(): string;
    /**
     * The ID of the internally created CloudFront Distribution.
     */
    get distributionId(): string;
    /**
     * The domain name of the internally created CloudFront Distribution.
     */
    get distributionDomain(): string;
    /**
     * Attaches the given list of permissions to allow the Next.js API routes and Server Side rendering `getServerSideProps` to access other AWS resources.
     * @example
     * ### Attaching permissions
     *
     * ```js {5}
     * const site = new NextjsSite(stack, "Site", {
     *   path: "path/to/site",
     * });
     *
     * site.attachPermissions(["sns"]);
     * ```
     */
    attachPermissions(permissions: Permissions): void;
    getConstructMetadata(): {
        type: "SlsNextjsSite";
        data: {
            path: string;
            environment: {
                [key: string]: string;
            };
            distributionId: string;
            customDomainUrl: string | undefined;
        };
    };
    /** @internal */
    getBindings(): BindingProps;
    private zipAppAssets;
    private zipAppStubAssets;
    private createEdgeFunction;
    private createEdgeFunctionInUE1;
    private createEdgeFunctionInNonUE1;
    private createEdgeFunctionRole;
    private createRegenerationQueue;
    private createRegenerationFunction;
    private createLambdaCodeReplacer;
    private createS3Bucket;
    private createS3Deployment;
    private buildApp;
    private runBuild;
    private runAfterBuild;
    private createCloudFrontDistribution;
    private createCloudFrontStaticCachePolicy;
    private createCloudFrontImageCachePolicy;
    private createCloudFrontLambdaCachePolicy;
    private createCloudFrontImageOriginRequestPolicy;
    private createCloudFrontInvalidation;
    protected validateCustomDomainSettings(): void;
    protected lookupHostedZone(): route53.IHostedZone | undefined;
    private createCertificate;
    protected createRoute53Records(): void;
    private pathPattern;
    private readRoutesManifest;
    private getS3ContentReplaceValues;
    private getLambdaContentReplaceValues;
    private normalizeRuntime;
}
export declare const useSites: () => {
    add(stack: string, name: string, props: NextjsSiteProps): void;
    readonly all: {
        stack: string;
        name: string;
        props: NextjsSiteProps;
    }[];
};
