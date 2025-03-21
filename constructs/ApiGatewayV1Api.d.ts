import { Construct } from "constructs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as iam from "aws-cdk-lib/aws-iam";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as apig from "aws-cdk-lib/aws-apigateway";
import * as apigV1AccessLog from "./util/apiGatewayV1AccessLog.js";
import { Bucket } from "./Bucket.js";
import { BindingResource, BindingProps } from "./util/binding.js";
import { Duration } from "./util/duration.js";
import { SSTConstruct } from "./Construct.js";
import { Function as Fn, FunctionProps, FunctionInlineDefinition, FunctionDefinition } from "./Function.js";
import { Permissions } from "./util/permission.js";
export interface ApiGatewayV1ApiAccessLogProps extends apigV1AccessLog.AccessLogProps {
}
export interface ApiGatewayV1ApiProps<Authorizers extends Record<string, ApiGatewayV1ApiAuthorizer> = Record<string, never>, AuthorizerKeys = keyof Authorizers> {
    /**
     * Define the routes for the API. Can be a function, proxy to another API, or point to an ALB
     *
     * @example
     *
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   "GET /notes"      : "src/list.main",
     *   "GET /notes/{id}" : "src/get.main",
     *   "$default": "src/default.main"
     * })
     * ```
     */
    routes?: Record<string, ApiGatewayV1ApiRouteProps<AuthorizerKeys>>;
    /**
     * CORS support applied to all endpoints in this API
     *
     * @example
     *
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   cors: true,
     * });
     * ```
     *
     */
    cors?: boolean;
    /**
     * Enable CloudWatch access logs for this API
     *
     * @example
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   accessLog: true
     * });
     *
     * ```
     * @example
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   accessLog: {
     *     retention: "one_week",
     *   },
     * });
     * ```
     */
    accessLog?: boolean | string | ApiGatewayV1ApiAccessLogProps;
    /**
     * Specify a custom domain to use in addition to the automatically generated one. SST currently supports domains that are configured using [Route 53](https://aws.amazon.com/route53/)
     *
     * @example
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   customDomain: "api.example.com"
     * })
     * ```
     *
     * @example
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   customDomain: {
     *     domainName: "api.example.com",
     *     hostedZone: "domain.com",
     *     path: "v1"
     *   }
     * })
     * ```
     */
    customDomain?: string | ApiGatewayV1ApiCustomDomainProps;
    /**
     * Define the authorizers for the API. Can be a user pool, JWT, or Lambda authorizers.
     *
     * @example
     * ```js
     * new ApiGatewayV1Api(stack, "Api", {
     *   authorizers: {
     *     MyAuthorizer: {
     *       type: "user_pools",
     *       userPoolIds: [userPool.userPoolId],
     *     },
     *   },
     * });
     * ```
     */
    authorizers?: Authorizers;
    defaults?: {
        /**
         * The default function props to be applied to all the Lambda functions in the API. The `environment`, `permissions` and `layers` properties will be merged with per route definitions if they are defined.
         *
         * @example
         * ```js
         * new ApiGatewayV1Api(stack, "Api", {
         *   defaults: {
         *     function: {
         *       timeout: 20,
         *       environment: { tableName: table.tableName },
         *       permissions: [table],
         *     }
         *   er
         * });
         * ```
         */
        function?: FunctionProps;
        /**
         * The authorizer for all the routes in the API.
         *
         * @example
         * ```js
         * new ApiGatewayV1Api(stack, "Api", {
         *   defaults: {
         *     authorizer: "iam",
         *   }
         * });
         * ```
         *
         * @example
         * ```js
         * new ApiGatewayV1Api(stack, "Api", {
         *   authorizers: {
         *     Authorizer: {
         *       type: "user_pools",
         *       userPoolIds: [userPool.userPoolId],
         *     },
         *   },
         *   defaults: {
         *     authorizer: "Authorizer",
         *   }
         * });
         * ```
         */
        authorizer?: "none" | "iam" | (string extends AuthorizerKeys ? Omit<AuthorizerKeys, "none" | "iam"> : AuthorizerKeys);
        /**
         * An array of scopes to include in the authorization when using `user_pool` or `jwt` authorizers. These will be merged with the scopes from the attached authorizer.
         * @default []
         */
        authorizationScopes?: string[];
    };
    cdk?: {
        /**
         * Allows you to override default id for this construct.
         */
        id?: string;
        /**
         * Override the internally created REST API.
         *
         * @example
         * ```js
         *
         * new ApiGatewayV1Api(stack, "Api", {
         *   cdk: {
         *     restApi: {
         *       description: "My api"
         *     }
         *   }
         * });
         * ```
         */
        restApi?: apig.IRestApi | apig.RestApiProps;
        /**
         * If you are importing an existing API Gateway REST API project, you can import existing route paths by providing a list of paths with their corresponding resource ids.
         *
         * @example
         * ```js
         * import { RestApi } from "aws-cdk-lib/aws-apigateway";
         *
         * new ApiGatewayV1Api(stack, "Api", {
         *   cdk: {
         *     restApi: RestApi.fromRestApiAttributes(stack, "ImportedApi", {
         *       restApiId,
         *       rootResourceId,
         *     }),
         *     importedPaths: {
         *       "/notes": "slx2bn",
         *       "/users": "uu8xs3",
         *     },
         *   }
         * });
         * ```
         *
         * API Gateway REST API is structured in a tree structure:
         *
         * - Each path part is a separate API Gateway resource object
         * - And a path part is a child resource of the preceding part
         *
         * So the part path `/notes`, is a child resource of the root resource `/`. And `/notes/{noteId}` is a child resource of `/notes`.
         * If `/notes` has been created in the imported API, you have to import it before creating the `/notes/{noteId}` child route.
         */
        importedPaths?: {
            [path: string]: string;
        };
    };
}
export type ApiGatewayV1ApiRouteProps<AuthorizerKeys> = FunctionInlineDefinition | ApiGatewayV1ApiFunctionRouteProps<AuthorizerKeys>;
/**
 * Specify a function route handler and configure additional options
 *
 * @example
 * ```js
 * api.addRoutes(props.stack, {
 *   "GET /notes/{id}": {
 *     type: "function",
 *     function: "src/get.main",
 *   }
 * });
 * ```
 */
export interface ApiGatewayV1ApiFunctionRouteProps<AuthorizerKeys = never> {
    function?: FunctionDefinition;
    authorizer?: "none" | "iam" | (string extends AuthorizerKeys ? Omit<AuthorizerKeys, "none" | "iam"> : AuthorizerKeys);
    authorizationScopes?: string[];
    cdk?: {
        method?: Omit<apig.MethodOptions, "authorizer" | "authorizationType" | "authorizationScopes">;
        integration?: apig.LambdaIntegrationOptions;
        /**
         * Use an existing Lambda function.
         */
        function?: lambda.IFunction;
    };
}
export type ApiGatewayV1ApiAuthorizer = ApiGatewayV1ApiUserPoolsAuthorizer | ApiGatewayV1ApiLambdaTokenAuthorizer | ApiGatewayV1ApiLambdaRequestAuthorizer;
interface ApiGatewayV1ApiBaseAuthorizer {
    /**
     * The name of the authorizer.
     */
    name?: string;
    /**
     * The amount of time the results are cached.
     * @default Not cached
     */
    resultsCacheTtl?: Duration;
}
/**
 * Specify a user pools authorizer and configure additional options.
 *
 * @example
 * ```js
 * new ApiGatewayV1Api(stack, "Api", {
 *   authorizers: {
 *     MyAuthorizer: {
 *       type: "user_pools",
 *       userPoolIds: [userPool.userPoolId],
 *     },
 *   },
 * });
 * ```
 */
export interface ApiGatewayV1ApiUserPoolsAuthorizer extends ApiGatewayV1ApiBaseAuthorizer {
    /**
     * String literal to signify that the authorizer is user pool authorizer.
     */
    type: "user_pools";
    /**
     * The ids of the user pools to use for authorization.
     */
    userPoolIds?: string[];
    /**
     * The identity source for which authorization is requested.
     */
    identitySource?: string;
    cdk?: {
        /**
         * This allows you to override the default settings this construct uses internally to create the authorizer.
         */
        authorizer: apig.CognitoUserPoolsAuthorizer;
    };
}
/**
 * Specify a Lambda TOKEN authorizer and configure additional options.
 *
 * @example
 * ```js
 * new ApiGatewayV1Api(stack, "Api", {
 *   authorizers: {
 *     MyAuthorizer: {
 *       type: "lambda_token",
 *       function: new Function(stack, "Authorizer", {
 *         handler: "test/lambda.handler"
 *       }),
 *       identitySources: [apig.IdentitySource.header("Authorization")],
 *     },
 *   },
 * });
 * ```
 */
export interface ApiGatewayV1ApiLambdaTokenAuthorizer extends ApiGatewayV1ApiBaseAuthorizer {
    /**
     * String literal to signify that the authorizer is Lambda TOKEN authorizer.
     */
    type: "lambda_token";
    /**
     * Used to create the authorizer function
     */
    function?: Fn;
    /**
     * The identity source for which authorization is requested.
     */
    identitySource?: string;
    /**
     * An regex to be matched against the authorization token.
     *
     * Note that when matched, the authorizer lambda is invoked, otherwise a 401 Unauthorized is returned to the client.
     */
    validationRegex?: string;
    cdk?: {
        /**
         * An IAM role for API Gateway to assume before calling the Lambda-based authorizer.
         */
        assumeRole?: iam.IRole;
        /**
         * This allows you to override the default settings this construct uses internally to create the authorizer.
         */
        authorizer?: apig.TokenAuthorizer;
    };
}
/**
 * Specify a Lambda REQUEST authorizer and configure additional options.
 *
 * @example
 * ```js
 * new ApiGatewayV1Api(stack, "Api", {
 *   authorizers: {
 *     MyAuthorizer: {
 *       type: "lambda_request",
 *       function: new Function(stack, "Authorizer", {
 *         handler: "test/lambda.handler"
 *       }),
 *       identitySources: [apig.IdentitySource.header("Authorization")],
 *     },
 *   },
 * });
 * ```
 */
export interface ApiGatewayV1ApiLambdaRequestAuthorizer extends ApiGatewayV1ApiBaseAuthorizer {
    /**
     * String literal to signify that the authorizer is Lambda REQUEST authorizer.
     */
    type: "lambda_request";
    /**
     * Used to create the authorizer function
     */
    function?: Fn;
    /**
     * The identity sources for which authorization is requested.
     */
    identitySources?: string[];
    cdk?: {
        /**
         * An IAM role for API Gateway to assume before calling the Lambda-based authorizer.
         */
        assumeRole?: iam.IRole;
        /**
         * This allows you to override the default settings this construct uses internally to create the authorizer.
         */
        authorizer?: apig.TokenAuthorizer;
    };
}
/**
 * The customDomain for this API. SST currently supports domains that are configured using Route 53. If your domains are hosted elsewhere, you can [follow this guide to migrate them to Route 53](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/MigratingDNS.html).
 *
 * @example
 * ```js
 * new ApiGatewayV1Api(stack, "Api", {
 *   customDomain: "api.domain.com",
 * });
 * ```
 *
 * @example
 * ```js
 * new ApiGatewayV1Api(stack, "Api", {
 *   customDomain: {
 *     domainName: "api.domain.com",
 *     hostedZone: "domain.com",
 *     endpointType: EndpointType.EDGE,
 *     path: "v1",
 *   }
 * });
 * ```
 *
 * Note that, SST automatically creates a Route 53 A record in the hosted zone to point the custom domain to the API Gateway domain.
 */
export interface ApiGatewayV1ApiCustomDomainProps {
    /**
     * The domain to be assigned to the API endpoint.
     */
    domainName?: string;
    /**
     * The hosted zone in Route 53 that contains the domain.
     *
     * By default, SST will look for a hosted zone by stripping out the first part of the domainName that's passed in. So, if your domainName is `api.domain.com`, SST will default the hostedZone to `domain.com`.
     */
    hostedZone?: string;
    /**
     * The base mapping for the custom domain. For example, by setting the `domainName` to `api.domain.com` and `path` to `v1`, the custom domain URL for the API will become `https://api.domain.com/v1`. If the path is not set, the custom domain URL will be `https://api.domain.com`.
     *
     * :::caution
     * You cannot change the path once it has been set.
     * :::
     *
     * Note, if the `path` was not defined initially, it cannot be defined later. If the `path` was initially defined, it cannot be later changed to _undefined_. Instead, you'd need to remove the `customDomain` option from the construct, deploy it. And then set it to the new path value.
     */
    path?: string;
    /**
     * The type of endpoint for this DomainName.
     * @default `regional`
     */
    endpointType?: Lowercase<keyof typeof apig.EndpointType>;
    mtls?: {
        /**
         * The bucket that the trust store is hosted in.
         */
        bucket: Bucket;
        /**
         * The key in S3 to look at for the trust store.
         */
        key: string;
        /**
         * The version of the S3 object that contains your truststore.
         *
         * To specify a version, you must have versioning enabled for the S3 bucket.
         */
        version?: string;
    };
    /**
     * The Transport Layer Security (TLS) version + cipher suite for this domain name.
     * @default `TLS 1.0`
     */
    securityPolicy?: "TLS 1.0" | "TLS 1.2";
    cdk?: {
        /**
         * Import the underlying API Gateway custom domain names.
         */
        domainName?: apig.IDomainName;
        /**
         * Import the underlying Route 53 hosted zone.
         */
        hostedZone?: route53.IHostedZone;
        /**
         * Import the underlying ACM certificate.
         */
        certificate?: acm.ICertificate;
    };
}
/**
 *
 * The `ApiGatewayV1Api` construct is a higher level CDK construct that makes it easy to create an API Gateway REST API.
 *
 * @example
 *
 * ```js
 * import { ApiGatewayV1Api } from "sst/constructs";
 *
 * new ApiGatewayV1Api(stack, "Api", {
 *   routes: {
 *     "GET    /notes"     : "src/list.main",
 *     "POST   /notes"     : "src/create.main",
 *     "GET    /notes/{id}": "src/get.main",
 *     "PUT    /notes/{id}": "src/update.main",
 *     "DELETE /notes/{id}": "src/delete.main",
 *   },
 * });
 * ```
 */
export declare class ApiGatewayV1Api<Authorizers extends Record<string, ApiGatewayV1ApiAuthorizer> = Record<string, never>> extends Construct implements SSTConstruct {
    readonly id: string;
    readonly cdk: {
        /**
         * The internally created rest API
         */
        restApi: apig.RestApi;
        /**
         * The internally created log group
         */
        accessLogGroup?: logs.LogGroup;
        /**
         * The internally created domain name
         */
        domainName?: apig.DomainName;
        /**
         * The internally created certificate
         */
        certificate?: acm.ICertificate;
    };
    private _deployment?;
    private _customDomainUrl?;
    private importedResources;
    private props;
    private functions;
    private authorizersData;
    private bindingForAllRoutes;
    private permissionsAttachedForAllRoutes;
    constructor(scope: Construct, id: string, props?: ApiGatewayV1ApiProps<Authorizers>);
    /**
     * The AWS generated URL of the Api.
     */
    get url(): string;
    /**
     * If custom domain is enabled, this is the custom domain URL of the Api.
     *
     * :::note
     * If you are setting the base mapping for the custom domain, you need to include the trailing slash while using the custom domain URL. For example, if the [`domainName`](#domainname) is set to `api.domain.com` and the [`path`](#path) is `v1`, the custom domain URL of the API will be `https://api.domain.com/v1/`.
     * :::
     */
    get customDomainUrl(): string | undefined;
    /**
     * The routes for the Api
     */
    get routes(): string[];
    /**
     * The ARN of the internally created API Gateway REST API
     */
    get restApiArn(): string;
    /**
     * The id of the internally created API Gateway REST API
     */
    get restApiId(): string;
    /**
     * Adds routes to the Api after it has been created.
     *
     * @example
     * ```js
     * api.addRoutes(stack, {
     *   "GET    /notes/{id}": "src/get.main",
     *   "PUT    /notes/{id}": "src/update.main",
     *   "DELETE /notes/{id}": "src/delete.main",
     * });
     * ```
     */
    addRoutes(scope: Construct, routes: Record<string, ApiGatewayV1ApiRouteProps<keyof Authorizers>>): void;
    /**
     * Get the instance of the internally created Function, for a given route key where the `routeKey` is the key used to define a route. For example, `GET /notes`.
     *
     * @example
     * ```js
     * const api = new ApiGatewayV1Api(stack, "Api", {
     *   routes: {
     *     "GET    /notes": "src/list.main",
     *   },
     * });
     *
     * const listFunction = api.getFunction("GET /notes");
     * ```
     */
    getFunction(routeKey: string): Fn | undefined;
    /**
     * Binds the given list of resources to all the routes.
     *
     * @example
     *
     * ```js
     * api.bind([STRIPE_KEY, bucket]);
     * ```
     */
    bind(constructs: BindingResource[]): void;
    /**
     * Binds the given list of resources to a specific route.
     *
     * @example
     * ```js
     * const api = new Api(stack, "Api", {
     *   routes: {
     *     "GET /notes": "src/list.main",
     *   },
     * });
     *
     * api.bindToRoute("GET /notes", [STRIPE_KEY, bucket]);
     * ```
     *
     */
    bindToRoute(routeKey: string, constructs: BindingResource[]): void;
    /**
     * Attaches the given list of permissions to all the routes. This allows the functions to access other AWS resources.
     *
     * @example
     *
     * ```js
     * api.attachPermissions(["s3"]);
     * ```
     */
    attachPermissions(permissions: Permissions): void;
    /**
     * Attaches the given list of permissions to a specific route. This allows that function to access other AWS resources.
     *
     * @example
     * ```js
     * const api = new ApiGatewayV1Api(stack, "Api", {
     *   routes: {
     *     "GET /notes": "src/list.main",
     *   },
     * });
     *
     * api.attachPermissionsToRoute("GET /notes", ["s3"]);
     * ```
     */
    attachPermissionsToRoute(routeKey: string, permissions: Permissions): void;
    getConstructMetadata(): {
        type: "ApiGatewayV1Api";
        data: {
            customDomainUrl: string | undefined;
            url: string;
            restApiId: string;
            routes: {
                type: "function";
                route: string;
                fn: {
                    node: string;
                    stack: string;
                } | undefined;
            }[];
        };
    };
    /** @internal */
    getBindings(): BindingProps;
    private createRestApi;
    private buildCorsConfig;
    private createGatewayResponseForCors;
    private createCustomDomain;
    private createARecords;
    private importResources;
    private getResourceForPath;
    private addAuthorizers;
    private addRoute;
    private createCdkFunction;
    private createFunction;
    private buildRouteMethodOptions;
    private normalizeRouteKey;
    private assertDomainNameIsLowerCase;
}
export {};
