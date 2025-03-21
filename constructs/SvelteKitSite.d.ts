import { SsrSite, SsrSiteNormalizedProps, SsrSiteProps } from "./SsrSite.js";
import { Construct } from "constructs";
export interface SvelteKitSiteProps extends SsrSiteProps {
    /**
     * The server function is deployed to Lambda in a single region. Alternatively, you can enable this option to deploy to Lambda@Edge.
     * @default false
     */
    edge?: boolean;
    /**
     * Configures the base path for the SvelteKit app.
     * Base path allows the app to live on a non-root path. The base path must start, but not end with /.
     * @default No base path
     * @example
     * ```js
     * basePath: '/docs'
     * ```
     */
    basePath?: `/${string}`;
}
type SvelteKitSiteNormalizedProps = SvelteKitSiteProps & SsrSiteNormalizedProps;
/**
 * The `SvelteKitSite` construct is a higher level CDK construct that makes it easy to create a SvelteKit app.
 * @example
 * Deploys a SvelteKit app in the `my-svelte-app` directory.
 *
 * ```js
 * new SvelteKitSite(stack, "web", {
 *   path: "my-svelte-app/",
 * });
 * ```
 */
export declare class SvelteKitSite extends SsrSite {
    props: SvelteKitSiteNormalizedProps;
    constructor(scope: Construct, id: string, props?: SvelteKitSiteProps);
    protected plan(): {
        cloudFrontFunctions?: {
            serverCfFunction: {
                constructId: string;
                injections: string[];
            };
        } | undefined;
        edgeFunctions?: {
            edgeServer: {
                constructId: string;
                function: {
                    description: string;
                    handler: string;
                    nodejs: {
                        esbuild: {
                            minify: boolean;
                            sourcemap: boolean | "inline";
                            define: {
                                "process.env.SST_DEBUG": string;
                            };
                        };
                    };
                    copyFiles: {
                        from: string;
                        to: string;
                    }[];
                    scopeOverride: SvelteKitSite;
                };
            };
        } | undefined;
        origins: {
            s3: {
                type: "s3";
                copy: ({
                    from: string;
                    to: string;
                    cached: true;
                    versionedSubDir: string;
                } | {
                    from: string;
                    to: string;
                    cached: false;
                    versionedSubDir?: undefined;
                })[];
            };
            regionalServer?: {
                type: "function";
                constructId: string;
                function: {
                    description: string;
                    handler: string;
                    nodejs: {
                        esbuild: {
                            minify: boolean;
                            sourcemap: boolean | "inline";
                            define: {
                                "process.env.SST_DEBUG": string;
                            };
                        };
                    };
                    copyFiles: {
                        from: string;
                        to: string;
                    }[];
                };
            } | undefined;
        };
        edge: boolean;
        behaviors: {
            cacheType: "server" | "static";
            pattern?: string | undefined;
            origin: "s3" | "regionalServer";
            allowedMethods?: import("aws-cdk-lib/aws-cloudfront").AllowedMethods | undefined;
            cfFunction?: "serverCfFunction" | undefined;
            edgeFunction?: "edgeServer" | undefined;
        }[];
        errorResponses?: import("aws-cdk-lib/aws-cloudfront").ErrorResponse[] | undefined;
        serverCachePolicy?: {
            allowedHeaders?: string[] | undefined;
        } | undefined;
        buildId?: string | undefined;
        warmer?: {
            function: string;
        } | undefined;
    };
    getConstructMetadata(): {
        data: {
            mode: "placeholder" | "deployed";
            path: string;
            runtime: "nodejs16.x" | "nodejs18.x" | "nodejs20.x" | "nodejs22.x";
            customDomainUrl: string | undefined;
            url: string | undefined;
            edge: boolean | undefined;
            server: string;
            secrets: string[];
            prefetchSecrets: boolean | undefined;
        };
        type: "SvelteKitSite";
    };
}
export {};
