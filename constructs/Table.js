import { Construct } from "constructs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import { getFunctionRef, isCDKConstruct } from "./Construct.js";
import { Function as Fn, } from "./Function.js";
/////////////////////
// Construct
/////////////////////
/**
 * The `Table` construct is a higher level CDK construct that makes it easy to create a DynamoDB table.
 *
 * @example
 *
 * Deploys a plain HTML website in the `path/to/src` directory.
 *
 * ```js
 * import { Table } from "sst/constructs";
 *
 * new Table(stack, "Notes", {
 *   fields: {
 *     userId: "string",
 *     noteId: "string",
 *   },
 *   primaryIndex: { partitionKey: "noteId", sortKey: "userId" },
 * });
 * ```
 */
export class Table extends Construct {
    id;
    cdk;
    dynamodbTableType;
    functions = {};
    bindingForAllConsumers = [];
    permissionsAttachedForAllConsumers = [];
    props;
    stream;
    fields;
    constructor(scope, id, props) {
        super(scope, props.cdk?.id || id);
        this.id = id;
        this.props = props;
        const { fields, globalIndexes, localIndexes, kinesisStream } = this.props;
        this.cdk = {};
        this.fields = fields;
        // Input Validation
        this.validateFieldsAndIndexes(id, props);
        // Create Table
        this.createTable();
        // Create Secondary Indexes
        if (globalIndexes)
            this.addGlobalIndexes(globalIndexes);
        if (localIndexes)
            this.addLocalIndexes(localIndexes);
        // Create Consumers
        if (props.consumers) {
            for (const consumerName in props.consumers) {
                this.addConsumer(this, consumerName, props.consumers[consumerName]);
            }
        }
        // Create Kinesis Stream
        this.buildKinesisStreamSpec(kinesisStream);
        const app = this.node.root;
        app.registerTypes(this);
    }
    /**
     * The ARN of the internally created DynamoDB Table.
     */
    get tableArn() {
        return this.cdk.table.tableArn;
    }
    /**
     * The name of the internally created DynamoDB Table.
     */
    get tableName() {
        return this.cdk.table.tableName;
    }
    /**
     * Add additional global secondary indexes where the `key` is the name of the global secondary index
     *
     * @example
     * ```js
     * table.addGlobalIndexes({
     *   gsi1: {
     *     partitionKey: "pk",
     *     sortKey: "sk",
     *   }
     * })
     * ```
     */
    addGlobalIndexes(secondaryIndexes) {
        if (!this.fields)
            throw new Error(`Cannot add secondary indexes to "${this.node.id}" Table without defining "fields"`);
        for (const [indexName, { partitionKey, sortKey, projection, cdk },] of Object.entries(secondaryIndexes)) {
            // Validate index does not contain "indexName", "partitionKey" and "sortKey"
            if (cdk?.index?.indexName) {
                throw new Error(`Cannot configure the "cdk.index.indexName" in the "${indexName}" index of the "${this.node.id}" Table`);
            }
            if (cdk?.index?.partitionKey) {
                throw new Error(`Cannot configure the "cdk.index.partitionKey" in the "${indexName}" index of the "${this.node.id}" Table`);
            }
            if (cdk?.index?.sortKey) {
                throw new Error(`Cannot configure the "cdk.index.sortKey" in the "${indexName}" index of the "${this.node.id}" Table`);
            }
            this.cdk.table.addGlobalSecondaryIndex({
                indexName,
                partitionKey: this.buildAttribute(this.fields, partitionKey),
                sortKey: sortKey
                    ? this.buildAttribute(this.fields, sortKey)
                    : undefined,
                ...(() => {
                    if (!projection) {
                        return undefined;
                    }
                    else if (Array.isArray(projection)) {
                        return {
                            projectionType: dynamodb.ProjectionType.INCLUDE,
                            nonKeyAttributes: projection,
                        };
                    }
                    return {
                        projectionType: dynamodb.ProjectionType[projection.toUpperCase()],
                    };
                })(),
                ...cdk?.index,
            });
        }
    }
    /**
     * Add additional local secondary indexes where the `key` is the name of the local secondary index
     *
     * @example
     * ```js
     * table.addLocalIndexes({
     *   lsi1: {
     *     sortKey: "sk",
     *   }
     * })
     * ```
     */
    addLocalIndexes(secondaryIndexes) {
        if (!this.fields)
            throw new Error(`Cannot add local secondary indexes to "${this.node.id}" Table without defining "fields"`);
        for (const [indexName, { sortKey, projection, cdk }] of Object.entries(secondaryIndexes)) {
            // Validate index does not contain "indexName", "partitionKey" and "sortKey"
            if (cdk?.index?.indexName) {
                throw new Error(`Cannot configure the "cdk.index.indexName" in the "${indexName}" index of the "${this.node.id}" Table`);
            }
            if (cdk?.index?.sortKey) {
                throw new Error(`Cannot configure the "cdk.index.sortKey" in the "${indexName}" index of the "${this.node.id}" Table`);
            }
            this.cdk.table.addLocalSecondaryIndex({
                indexName,
                sortKey: this.buildAttribute(this.fields, sortKey),
                ...(() => {
                    if (!projection) {
                        return undefined;
                    }
                    else if (Array.isArray(projection)) {
                        return {
                            projectionType: dynamodb.ProjectionType.INCLUDE,
                            nonKeyAttributes: projection,
                        };
                    }
                    return {
                        projectionType: dynamodb.ProjectionType[projection.toUpperCase()],
                    };
                })(),
                ...cdk?.index,
            });
        }
    }
    /**
     * Define additional consumers for table events
     *
     * @example
     * ```js
     * table.addConsumers(stack, {
     *   consumer1: "src/consumer1.main",
     *   consumer2: "src/consumer2.main",
     * });
     * ```
     */
    addConsumers(scope, consumers) {
        Object.keys(consumers).forEach((consumerName) => {
            this.addConsumer(scope, consumerName, consumers[consumerName]);
        });
    }
    /**
     * Binds the given list of resources to all consumers of this table.
     *
     * @example
     * ```js
     * table.bind([STRIPE_KEY, bucket]);
     * ```
     */
    bind(constructs) {
        Object.values(this.functions).forEach((fn) => fn.bind(constructs));
        this.bindingForAllConsumers.push(...constructs);
    }
    /**
     * Binds the given list of resources to a specific consumer of this table.
     *
     * @example
     * ```js
     * table.bindToConsumer("consumer1", [STRIPE_KEY, bucket]);
     * ```
     */
    bindToConsumer(consumerName, constructs) {
        if (!this.functions[consumerName]) {
            throw new Error(`The "${consumerName}" consumer was not found in the "${this.node.id}" Table.`);
        }
        this.functions[consumerName].bind(constructs);
    }
    /**
     * Grant permissions to all consumers of this table.
     *
     * @example
     * ```js
     * table.attachPermissions(["s3"]);
     * ```
     */
    attachPermissions(permissions) {
        Object.values(this.functions).forEach((fn) => fn.attachPermissions(permissions));
        this.permissionsAttachedForAllConsumers.push(permissions);
    }
    /**
     * Grant permissions to a specific consumer of this table.
     *
     * @example
     * ```js
     * table.attachPermissionsToConsumer("consumer1", ["s3"]);
     * ```
     */
    attachPermissionsToConsumer(consumerName, permissions) {
        if (!this.functions[consumerName]) {
            throw new Error(`The "${consumerName}" consumer was not found in the "${this.node.id}" Table.`);
        }
        this.functions[consumerName].attachPermissions(permissions);
    }
    /**
     * Get the instance of the internally created Function, for a given consumer.
     *
     * ```js
     *  const table = new Table(stack, "Table", {
     *    consumers: {
     *      consumer1: "./src/function.handler",
     *    }
     *  })
     * table.getFunction("consumer1");
     * ```
     */
    getFunction(consumerName) {
        return this.functions[consumerName];
    }
    /** @internal */
    getConstructMetadata() {
        return {
            type: "Table",
            data: {
                tableName: this.cdk.table.tableName,
                consumers: Object.entries(this.functions).map(([name, fun]) => ({
                    name,
                    fn: getFunctionRef(fun),
                })),
            },
        };
    }
    /** @internal */
    getBindings() {
        return {
            clientPackage: "table",
            variables: {
                tableName: {
                    type: "plain",
                    value: this.tableName,
                },
            },
            permissions: {
                "dynamodb:*": [this.tableArn, `${this.tableArn}/*`],
            },
        };
    }
    createTable() {
        const { fields, primaryIndex, stream, timeToLiveAttribute, cdk } = this.props;
        const app = this.node.root;
        const id = this.node.id;
        if (isCDKConstruct(cdk?.table)) {
            // Validate "fields" is not configured
            if (fields !== undefined) {
                throw new Error(`Cannot configure the "fields" when "cdk.table" is a construct in the "${id}" Table`);
            }
            // Validate "stream" is not configured
            if (stream !== undefined) {
                throw new Error(`Cannot configure the "stream" when "cdk.table" is a construct in the "${id}" Table`);
            }
            this.dynamodbTableType = "IMPORTED";
            this.cdk.table = cdk?.table;
        }
        else {
            let dynamodbTableProps = (cdk?.table || {});
            // Validate "fields" is configured
            if (fields === undefined) {
                throw new Error(`Missing "fields" in the "${id}" Table`);
            }
            // Validate dynamodbTableProps does not contain "partitionKey", "sortKey" and "stream"
            if (dynamodbTableProps.partitionKey) {
                throw new Error(`Cannot configure the "cdk.table.partitionKey" in the "${id}" Table`);
            }
            if (dynamodbTableProps.sortKey) {
                throw new Error(`Cannot configure the "cdk.table.sortKey" in the "${id}" Table`);
            }
            if (dynamodbTableProps.stream) {
                throw new Error(`Cannot configure the "cdk.table.stream" in the "${id}" Table`);
            }
            if (fields && primaryIndex) {
                dynamodbTableProps = {
                    ...dynamodbTableProps,
                    partitionKey: this.buildAttribute(fields, primaryIndex.partitionKey),
                    sortKey: primaryIndex.sortKey
                        ? this.buildAttribute(fields, primaryIndex.sortKey)
                        : undefined,
                };
            }
            this.dynamodbTableType = "CREATED";
            this.cdk.table = new dynamodb.Table(this, "Table", {
                tableName: app.logicalPrefixedName(id),
                pointInTimeRecovery: true,
                billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
                stream: this.buildStreamConfig(stream),
                timeToLiveAttribute,
                ...dynamodbTableProps,
            });
        }
    }
    addConsumer(scope, consumerName, consumer) {
        // validate stream enabled
        // note: if table is imported, do not check because we want to allow ppl to
        //       import without specifying the "tableStreamArn". And let them add
        //       consumers to it.
        if (!this.cdk.table.tableStreamArn) {
            const errorMsgs = [
                `Please enable the "stream" option to add consumers to the "${this.node.id}" Table.`,
            ];
            if (this.dynamodbTableType === "IMPORTED") {
                errorMsgs.push(`To import a table with stream enabled, use the "Table.fromTableAttributes()" method, and set the "tableStreamArn" in the attributes.`);
            }
            throw new Error(errorMsgs.join(" "));
        }
        // parse consumer
        let consumerFunction, eventSourceProps, filters;
        if (consumer.function) {
            consumer = consumer;
            consumerFunction = consumer.function;
            eventSourceProps = consumer.cdk?.eventSource;
            filters = consumer.filters;
        }
        else {
            consumerFunction = consumer;
        }
        // create function
        const fn = Fn.fromDefinition(scope, `Consumer_${this.node.id}_${consumerName}`, consumerFunction, this.props.defaults?.function, `The "defaults.function" cannot be applied if an instance of a Function construct is passed in. Make sure to define all the consumers using FunctionProps, so the Table construct can apply the "defaults.function" to them.`);
        this.functions[consumerName] = fn;
        // create event source
        fn.addEventSource(new lambdaEventSources.DynamoEventSource(this.cdk.table, {
            startingPosition: lambda.StartingPosition.LATEST,
            filters: filters?.map((filter) => ({
                pattern: JSON.stringify(filter),
            })),
            ...(eventSourceProps || {}),
        }));
        // attach permissions
        this.permissionsAttachedForAllConsumers.forEach((permissions) => {
            fn.attachPermissions(permissions);
        });
        fn.bind(this.bindingForAllConsumers);
        return fn;
    }
    buildAttribute(fields, name) {
        // Ensure the key is specified in "fields"
        if (!fields[name]) {
            throw new Error(`Please define "${name}" in "fields" to create the index in the "${this.node.id}" Table.`);
        }
        return {
            name,
            type: dynamodb.AttributeType[fields[name].toUpperCase()],
        };
    }
    buildStreamConfig(stream) {
        if (stream === true) {
            return dynamodb.StreamViewType.NEW_AND_OLD_IMAGES;
        }
        else if (stream === false || stream === undefined) {
            return undefined;
        }
        return dynamodb.StreamViewType[stream.toUpperCase()];
    }
    buildKinesisStreamSpec(kinesisStream) {
        if (!kinesisStream) {
            return;
        }
        const cfTable = this.cdk.table.node.defaultChild;
        cfTable.addPropertyOverride("KinesisStreamSpecification.StreamArn", kinesisStream.streamArn);
    }
    validateFieldsAndIndexes(id, props) {
        const { fields, primaryIndex } = props;
        // Validate "fields"
        if (fields && Object.keys(fields).length === 0) {
            throw new Error(`No fields defined for the "${id}" Table`);
        }
        // Validate "primaryIndex"
        if (primaryIndex && !primaryIndex.partitionKey) {
            throw new Error(`Missing "partitionKey" in primary index for the "${id}" Table`);
        }
        // Validate "fields" and "primaryIndex" co-exists
        if (fields) {
            if (!primaryIndex) {
                throw new Error(`Missing "primaryIndex" in "${id}" Table`);
            }
        }
        else {
            if (primaryIndex) {
                throw new Error(`Cannot configure the "primaryIndex" without setting the "fields" in "${id}" Table`);
            }
        }
    }
}
