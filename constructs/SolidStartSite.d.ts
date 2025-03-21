import { SsrSite, SsrSiteNormalizedProps, SsrSiteProps } from "./SsrSite.js";
import { Construct } from "constructs";
export interface SolidStartSiteProps extends SsrSiteProps {
    /**
     * The server function is deployed to Lambda in a single region. Alternatively, you can enable this option to deploy to Lambda@Edge.
     * @default false
     */
    edge?: boolean;
}
type SolidStartSiteNormalizedProps = SolidStartSiteProps & SsrSiteNormalizedProps;
/**
 * The `SolidStartSite` construct is a higher level CDK construct that makes it easy to create a SolidStart app.
 * @example
 * Deploys a SolidStart app in the `my-solid-start-app` directory.
 *
 * ```js
 * new SolidStartSite(stack, "web", {
 *   path: "my-solid-start-app/",
 * });
 * ```
 */
export declare class SolidStartSite extends SsrSite {
    props: SolidStartSiteNormalizedProps;
    constructor(scope: Construct, id: string, props?: SolidStartSiteProps);
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
                    scopeOverride: SolidStartSite;
                };
            };
        } | undefined;
        origins: {
            s3: {
                type: "s3";
                copy: {
                    from: string;
                    to: string;
                    cached: true;
                    versionedSubDir: string;
                }[];
            };
            regionalServer?: {
                type: "function";
                constructId: string;
                function: {
                    description: string;
                    handler: string;
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
        type: "SolidStartSite";
    };
}
export {};
