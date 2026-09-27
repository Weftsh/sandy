/**
 * DynamoDB store. One table per record type (created by the CloudFormation
 * stack), each keyed by a single string attribute; sandboxes have a
 * `teamId-index` GSI. Sandbox updates are conditional on `version`.
 */
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  type ScanCommandInput,
  type QueryCommandInput,
} from "@aws-sdk/lib-dynamodb";

import { VersionConflict, type ApiKey, type BuildRecord, type Host, type Sandbox, type Store, type Team, type Template } from "./types.js";

export const TABLES = {
  teams: { name: "teams", key: "teamId" },
  apikeys: { name: "apikeys", key: "keyHash" },
  templates: { name: "templates", key: "templateId" },
  builds: { name: "builds", key: "buildId" },
  sandboxes: { name: "sandboxes", key: "sandboxId" },
  hosts: { name: "hosts", key: "hostId" },
  meta: { name: "meta", key: "key" },
} as const;

type TableName = keyof typeof TABLES;

/**
 * Table definitions matching the CloudFormation stack, for local development
 * and tests against DynamoDB Local.
 */
export function tableDefinitions(prefix: string) {
  return (Object.keys(TABLES) as TableName[]).map((t) => ({
    TableName: `${prefix}${TABLES[t].name}`,
    BillingMode: "PAY_PER_REQUEST" as const,
    AttributeDefinitions: [
      { AttributeName: TABLES[t].key, AttributeType: "S" as const },
      ...(t === "sandboxes" ? [{ AttributeName: "teamId", AttributeType: "S" as const }] : []),
    ],
    KeySchema: [{ AttributeName: TABLES[t].key, KeyType: "HASH" as const }],
    ...(t === "sandboxes"
      ? {
          GlobalSecondaryIndexes: [
            { IndexName: "teamId-index", KeySchema: [{ AttributeName: "teamId", KeyType: "HASH" as const }], Projection: { ProjectionType: "ALL" as const } },
          ],
        }
      : {}),
  }));
}

export class DynamoStore implements Store {
  private doc: DynamoDBDocumentClient;

  constructor(
    private prefix: string,
    client: DynamoDBClient,
  ) {
    this.doc = DynamoDBDocumentClient.from(client, {
      marshallOptions: { removeUndefinedValues: true, convertClassInstanceToMap: false },
    });
  }

  table(t: TableName): string {
    return `${this.prefix}${TABLES[t].name}`;
  }

  private async get<T>(t: TableName, id: string): Promise<T | undefined> {
    const out = await this.doc.send(new GetCommand({ TableName: this.table(t), Key: { [TABLES[t].key]: id }, ConsistentRead: true }));
    return out.Item as T | undefined;
  }

  private async put(t: TableName, item: object): Promise<void> {
    await this.doc.send(new PutCommand({ TableName: this.table(t), Item: item as Record<string, unknown> }));
  }

  private async del(t: TableName, id: string): Promise<void> {
    await this.doc.send(new DeleteCommand({ TableName: this.table(t), Key: { [TABLES[t].key]: id } }));
  }

  private async scan<T>(t: TableName, extra: Partial<ScanCommandInput> = {}): Promise<T[]> {
    const items: T[] = [];
    let start: Record<string, unknown> | undefined;
    do {
      const out = await this.doc.send(
        new ScanCommand({ TableName: this.table(t), ConsistentRead: true, ExclusiveStartKey: start, ...extra }),
      );
      items.push(...((out.Items ?? []) as T[]));
      start = out.LastEvaluatedKey;
    } while (start);
    return items;
  }

  private async query<T>(input: QueryCommandInput): Promise<T[]> {
    const items: T[] = [];
    let start: Record<string, unknown> | undefined;
    do {
      const out = await this.doc.send(new QueryCommand({ ...input, ExclusiveStartKey: start }));
      items.push(...((out.Items ?? []) as T[]));
      start = out.LastEvaluatedKey;
    } while (start);
    return items;
  }

  putTeam = (t: Team) => this.put("teams", t);
  getTeam = (id: string) => this.get<Team>("teams", id);
  listTeams = () => this.scan<Team>("teams");

  putApiKey = (k: ApiKey) => this.put("apikeys", k);
  getApiKeyByHash = (h: string) => this.get<ApiKey>("apikeys", h);
  listApiKeys = (teamId: string) =>
    this.scan<ApiKey>("apikeys", { FilterExpression: "teamId = :t", ExpressionAttributeValues: { ":t": teamId } });
  deleteApiKey = (h: string) => this.del("apikeys", h);

  // Templates store `teamId: null` for public ones; DynamoDB keeps nulls.
  putTemplate = (t: Template) => this.put("templates", t);
  getTemplate = (id: string) => this.get<Template>("templates", id);
  listTemplatesVisibleTo = async (teamId: string) =>
    (await this.scan<Template>("templates")).filter((t) => t.teamId === null || t.teamId === teamId);
  listAllTemplates = () => this.scan<Template>("templates");
  deleteTemplate = (id: string) => this.del("templates", id);

  putBuild = (b: BuildRecord) => this.put("builds", b);
  getBuild = (id: string) => this.get<BuildRecord>("builds", id);

  async createSandbox(s: Sandbox): Promise<void> {
    try {
      await this.doc.send(
        new PutCommand({ TableName: this.table("sandboxes"), Item: s as unknown as Record<string, unknown>, ConditionExpression: "attribute_not_exists(sandboxId)" }),
      );
    } catch (e) {
      if (e instanceof ConditionalCheckFailedException) throw new VersionConflict(s.sandboxId);
      throw e;
    }
  }

  async updateSandbox(s: Sandbox): Promise<void> {
    try {
      await this.doc.send(
        new PutCommand({
          TableName: this.table("sandboxes"),
          Item: s as unknown as Record<string, unknown>,
          ConditionExpression: "#v = :prev",
          ExpressionAttributeNames: { "#v": "version" },
          ExpressionAttributeValues: { ":prev": s.version - 1 },
        }),
      );
    } catch (e) {
      if (e instanceof ConditionalCheckFailedException) throw new VersionConflict(s.sandboxId);
      throw e;
    }
  }

  getSandbox = (id: string) => this.get<Sandbox>("sandboxes", id);
  deleteSandbox = (id: string) => this.del("sandboxes", id);
  listSandboxesByTeam = (teamId: string) =>
    this.query<Sandbox>({
      TableName: this.table("sandboxes"),
      IndexName: "teamId-index",
      KeyConditionExpression: "teamId = :t",
      ExpressionAttributeValues: { ":t": teamId },
    });
  listAllSandboxes = () => this.scan<Sandbox>("sandboxes");

  putHost = (h: Host) => this.put("hosts", h);
  getHost = (id: string) => this.get<Host>("hosts", id);
  listHosts = () => this.scan<Host>("hosts");
  deleteHost = (id: string) => this.del("hosts", id);

  async getMeta<T>(key: string): Promise<T | undefined> {
    const item = await this.get<{ key: string; value: T }>("meta", key);
    return item?.value;
  }
  async putMeta<T>(key: string, value: T): Promise<void> {
    await this.put("meta", { key, value });
  }
}
