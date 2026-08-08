import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { compareCanonicalStrings } from './canonical-order.mjs'

const { posix } = path

export const DATABASE_DISCOVERY_SCHEMA_VERSION = '1.0.0'
export const DATABASE_DISCOVERY_KIND = 'red-team-audit/database-discovery'

const DATABASE_DISCOVERY_SCHEMA_URL = new URL(
  '../../schemas/database-discovery.schema.json',
  import.meta.url,
)
const databaseDiscoverySchema = JSON.parse(
  readFileSync(fileURLToPath(DATABASE_DISCOVERY_SCHEMA_URL), 'utf8'),
)
const schemaAjv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  validateFormats: false,
})
const validateDatabaseDiscoverySchema = schemaAjv.compile(
  databaseDiscoverySchema,
)

const DEFAULT_LIMITS = Object.freeze({
  max_nodes: 10_000,
  max_edges: 20_000,
  max_rounds: 32,
  max_token_fanout: 64,
})
const HARD_LIMITS = Object.freeze({
  max_nodes: 50_000,
  max_edges: 100_000,
  max_rounds: 64,
  max_token_fanout: 1_024,
  max_inventory_entries: 100_000,
  max_text_bytes: 512 * 1024 * 1024,
  max_single_text_bytes: 16 * 1024 * 1024,
  max_resource_matches: 256,
})

const MANIFEST_NAMES = new Set([
  'package.json',
  'pyproject.toml',
  'requirements.txt',
  'go.mod',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'gemfile',
  'composer.json',
  'cargo.toml',
  'mix.exs',
])

const SOURCE_EXTENSIONS = [
  '',
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.json',
  '.bicep',
  '.tf',
  '.cs',
]

const CLIENT_PACKAGES = Object.freeze([
  { package: 'pg', engine: 'postgresql', signature: 'client.node.pg' },
  { package: 'postgres', engine: 'postgresql', signature: 'client.node.postgres-js' },
  {
    package: '@supabase/supabase-js',
    engine: 'postgresql',
    deployment: 'supabase',
    signature: 'client.node.supabase',
  },
  { package: 'mysql', engine: 'mysql', signature: 'client.node.mysql' },
  { package: 'mysql2', engine: 'mysql', signature: 'client.node.mysql2' },
  { package: 'mariadb', engine: 'mariadb', signature: 'client.node.mariadb' },
  { package: 'mssql', engine: 'sqlserver', signature: 'client.node.mssql' },
  { package: 'tedious', engine: 'sqlserver', signature: 'client.node.tedious' },
  { package: 'oracledb', engine: 'oracle', signature: 'client.node.oracledb' },
  { package: 'sqlite3', engine: 'sqlite', signature: 'client.node.sqlite3' },
  {
    package: 'better-sqlite3',
    engine: 'sqlite',
    signature: 'client.node.better-sqlite3',
  },
  { package: 'mongodb', engine: 'mongodb', signature: 'client.node.mongodb' },
  { package: 'mongoose', engine: 'mongodb', signature: 'client.node.mongoose' },
  { package: 'redis', engine: 'redis', signature: 'client.node.redis' },
  { package: 'ioredis', engine: 'redis', signature: 'client.node.ioredis' },
  {
    package: '@upstash/redis',
    engine: 'redis',
    deployment: 'upstash',
    signature: 'client.node.upstash-redis',
  },
  {
    package: '@neondatabase/serverless',
    engine: 'postgresql',
    deployment: 'neon',
    signature: 'client.node.neon',
  },
  {
    package: '@vercel/postgres',
    engine: 'postgresql',
    deployment: 'vercel-postgres',
    signature: 'client.node.vercel-postgres',
  },
  {
    package: '@planetscale/database',
    engine: 'mysql',
    deployment: 'planetscale',
    signature: 'client.node.planetscale',
  },
  {
    package: '@libsql/client',
    engine: 'sqlite',
    deployment: 'libsql',
    signature: 'client.node.libsql',
  },
  {
    package: 'firebase-admin',
    engine: null,
    deployment: 'firebase',
    signature: 'client.node.firebase-admin',
  },
  {
    package: '@google-cloud/firestore',
    engine: 'firestore',
    deployment: 'google-cloud',
    signature: 'client.node.firestore',
  },
  {
    package: '@aws-sdk/client-dynamodb',
    engine: 'dynamodb',
    deployment: 'aws',
    signature: 'client.node.dynamodb-v3',
  },
  {
    package: 'aws-sdk',
    engine: null,
    deployment: 'aws',
    signature: 'client.node.aws-sdk-generic',
  },
  {
    package: '@elastic/elasticsearch',
    engine: 'elasticsearch',
    signature: 'client.node.elasticsearch',
  },
  {
    package: '@opensearch-project/opensearch',
    engine: 'opensearch',
    signature: 'client.node.opensearch',
  },
  {
    package: 'cassandra-driver',
    engine: 'cassandra',
    signature: 'client.node.cassandra',
  },
  { package: 'neo4j-driver', engine: 'neo4j', signature: 'client.node.neo4j' },
  { package: 'snowflake-sdk', engine: 'snowflake', signature: 'client.node.snowflake' },
  {
    package: '@google-cloud/bigquery',
    engine: 'bigquery',
    deployment: 'google-cloud',
    signature: 'client.node.bigquery',
  },
  {
    package: '@pinecone-database/pinecone',
    engine: 'pinecone',
    signature: 'client.node.pinecone',
  },
  {
    package: '@qdrant/js-client-rest',
    engine: 'qdrant',
    signature: 'client.node.qdrant',
  },
  {
    package: 'weaviate-ts-client',
    engine: 'weaviate',
    signature: 'client.node.weaviate',
  },
  { package: '@prisma/client', engine: null, signature: 'client.node.prisma' },
  { package: 'drizzle-orm', engine: null, signature: 'client.node.drizzle' },
  { package: 'typeorm', engine: null, signature: 'client.node.typeorm' },
  { package: 'sequelize', engine: null, signature: 'client.node.sequelize' },
  { package: 'knex', engine: null, signature: 'client.node.knex' },
  { package: 'kysely', engine: null, signature: 'client.node.kysely' },
  { package: '@mikro-orm/core', engine: null, signature: 'client.node.mikro-orm' },
])

const CLIENT_PACKAGES_BY_SPECIFICITY = Object.freeze(
  [...CLIENT_PACKAGES].sort((left, right) =>
    right.package.length - left.package.length || compareText(left.package, right.package)),
)

const LANGUAGE_CLIENTS = Object.freeze([
  {
    pattern: /\b(?:import|from)\s+(?:psycopg2|psycopg|asyncpg)\b/g,
    engine: 'postgresql',
    signature: 'client.python.postgresql',
  },
  {
    pattern: /\b(?:import|from)\s+(?:pymysql|mysql\.connector)\b/g,
    engine: 'mysql',
    signature: 'client.python.mysql',
  },
  {
    pattern: /\b(?:import|from)\s+(?:pymongo|motor)\b/g,
    engine: 'mongodb',
    signature: 'client.python.mongodb',
  },
  {
    pattern: /\b(?:import|from)\s+redis\b/g,
    engine: 'redis',
    signature: 'client.python.redis',
  },
  {
    pattern: /\b(?:import|from)\s+(?:snowflake\.connector|snowflake)\b/g,
    engine: 'snowflake',
    signature: 'client.python.snowflake',
  },
  {
    pattern:
      /\bboto3\s*\.\s*(?:client|resource)\s*\(\s*['"]dynamodb['"]/g,
    pathPattern: /\.py$/i,
    engine: 'dynamodb',
    signature: 'client.python.boto3-dynamodb-service',
  },
  {
    pattern:
      /\b(?:from\s+google\.cloud\s+import\s+firestore|from\s+google\.cloud\.firestore\s+import)\b/g,
    pathPattern: /\.py$/i,
    engine: 'firestore',
    signature: 'client.python.firestore',
  },
  {
    pattern:
      /\b(?:from\s+google\.cloud\s+import\s+bigquery|from\s+google\.cloud\.bigquery\s+import)\b/g,
    pathPattern: /\.py$/i,
    engine: 'bigquery',
    signature: 'client.python.bigquery',
  },
  {
    pattern: /\b(?:from|import)\s+elasticsearch\b/g,
    pathPattern: /\.py$/i,
    engine: 'elasticsearch',
    signature: 'client.python.elasticsearch',
  },
  {
    pattern: /\b(?:from|import)\s+opensearchpy\b/g,
    pathPattern: /\.py$/i,
    engine: 'opensearch',
    signature: 'client.python.opensearch',
  },
  {
    pattern: /\b(?:from|import)\s+neo4j\b/g,
    pathPattern: /\.py$/i,
    engine: 'neo4j',
    signature: 'client.python.neo4j',
  },
  {
    pattern: /\bfrom\s+cassandra(?:\.cluster)?\s+import\b/g,
    pathPattern: /\.py$/i,
    engine: 'cassandra',
    signature: 'client.python.cassandra',
  },
  {
    pattern: /\b(?:from|import)\s+pinecone\b/g,
    pathPattern: /\.py$/i,
    engine: 'pinecone',
    signature: 'client.python.pinecone',
  },
  {
    pattern: /\b(?:from|import)\s+qdrant_client\b/g,
    pathPattern: /\.py$/i,
    engine: 'qdrant',
    signature: 'client.python.qdrant',
  },
  {
    pattern: /\b(?:from|import)\s+weaviate\b/g,
    pathPattern: /\.py$/i,
    engine: 'weaviate',
    signature: 'client.python.weaviate',
  },
  {
    pattern:
      /\b(?:new\s+AWS\.DynamoDB(?:\.DocumentClient)?|DynamoDB(?:Document)?Client)\b/g,
    engine: 'dynamodb',
    signature: 'client.aws.dynamodb-service-api',
  },
  {
    pattern: /\b(?:getFirestore|admin\.firestore)\s*\(/g,
    engine: 'firestore',
    signature: 'client.firebase.firestore-service-api',
  },
  {
    pattern: /\bNpgsql(?:Connection|DataSource)\b/g,
    engine: 'postgresql',
    signature: 'client.dotnet.npgsql',
  },
  {
    pattern: /\bSqlConnection\b/g,
    engine: 'sqlserver',
    signature: 'client.dotnet.sqlclient',
  },
  {
    pattern: /\bMongoClient\b/g,
    engine: 'mongodb',
    signature: 'client.generic.mongodb',
  },
  {
    pattern: /\b(?:DriverManager\.getConnection|JdbcTemplate)\b/g,
    engine: null,
    signature: 'client.jvm.jdbc',
  },
  {
    pattern: /\b(?:import|from)\s+(?:sqlalchemy|django\.db)\b/g,
    engine: null,
    signature: 'client.python.orm',
  },
  {
    pattern: /\b(?:DbContext|EntityFrameworkCore)\b/g,
    engine: null,
    signature: 'client.dotnet.entity-framework',
  },
  {
    pattern:
      /['"](?:github\.com\/jackc\/pgx|github\.com\/lib\/pq)(?:\/[^'"]*)?['"]/g,
    engine: 'postgresql',
    signature: 'client.go.postgresql',
  },
  {
    pattern: /['"]github\.com\/go-sql-driver\/mysql(?:\/[^'"]*)?['"]/g,
    engine: 'mysql',
    signature: 'client.go.mysql',
  },
  {
    pattern: /['"](?:go\.mongodb\.org\/mongo-driver|github\.com\/mongodb\/mongo-go-driver)(?:\/[^'"]*)?['"]/g,
    engine: 'mongodb',
    signature: 'client.go.mongodb',
  },
  {
    pattern: /['"]github\.com\/redis\/go-redis(?:\/[^'"]*)?['"]/g,
    engine: 'redis',
    signature: 'client.go.redis',
  },
  {
    pattern: /['"]database\/sql['"]/g,
    engine: null,
    signature: 'client.go.database-sql',
  },
  {
    pattern: /\borg\.postgresql\.(?:Driver|ds\.)\b/g,
    engine: 'postgresql',
    signature: 'client.jvm.postgresql',
  },
  {
    pattern: /\bcom\.mysql\.cj\.jdbc\b/g,
    engine: 'mysql',
    signature: 'client.jvm.mysql',
  },
  {
    pattern: /\bcom\.microsoft\.sqlserver\.jdbc\b/g,
    engine: 'sqlserver',
    signature: 'client.jvm.sqlserver',
  },
  {
    pattern: /\brequire\s+['"]pg['"]/g,
    engine: 'postgresql',
    signature: 'client.ruby.pg',
  },
  {
    pattern: /\brequire\s+['"]redis['"]/g,
    engine: 'redis',
    signature: 'client.ruby.redis',
  },
])

const RESOURCE_SIGNATURES = Object.freeze([
  {
    pattern:
      /\bresource\s+([A-Za-z_][A-Za-z0-9_]*)\s+['"]Microsoft\.DBforPostgreSQL\/flexibleServers@[^'"]+['"]/g,
    engine: 'postgresql',
    deployment: 'azure-postgresql-flexible-server',
    signature: 'resource.azure.postgresql-flexible-server',
    versionPattern: /\bversion\s*:\s*['"]([0-9][0-9A-Za-z._+-]*)['"]/,
  },
  {
    pattern:
      /\bresource\s+([A-Za-z_][A-Za-z0-9_]*)\s+['"]Microsoft\.DBforMySQL\/flexibleServers@[^'"]+['"]/g,
    engine: 'mysql',
    deployment: 'azure-mysql-flexible-server',
    signature: 'resource.azure.mysql-flexible-server',
    versionPattern: /\bversion\s*:\s*['"]([0-9][0-9A-Za-z._+-]*)['"]/,
  },
  {
    pattern:
      /\bresource\s+([A-Za-z_][A-Za-z0-9_]*)\s+['"]Microsoft\.Cache\/redis@[^'"]+['"]/gi,
    engine: 'redis',
    deployment: 'azure-cache-for-redis',
    signature: 'resource.azure.redis',
  },
  {
    pattern:
      /\bresource\s+([A-Za-z_][A-Za-z0-9_]*)\s+['"]Microsoft\.Cache\/redisEnterprise@[^'"]+['"]/gi,
    engine: 'redis',
    deployment: 'azure-managed-redis',
    signature: 'resource.azure.redis-enterprise',
  },
  {
    pattern:
      /\bresource\s+([A-Za-z_][A-Za-z0-9_]*)\s+['"]Microsoft\.DocumentDB\/databaseAccounts@[^'"]+['"]/g,
    engine: null,
    deployment: 'azure-cosmos-db',
    signature: 'resource.azure.cosmos-db',
    enginePattern: /\bkind\s*:\s*['"]MongoDB['"]/i,
  },
  {
    pattern:
      /['"]type['"]\s*:\s*['"]Microsoft\.DBforPostgreSQL\/flexibleServers['"]/gi,
    engine: 'postgresql',
    deployment: 'azure-postgresql-flexible-server',
    signature: 'resource.azure-arm.postgresql-flexible-server',
    versionPattern: /['"]version['"]\s*:\s*['"]([0-9][0-9A-Za-z._+-]*)['"]/,
  },
  {
    pattern:
      /['"]type['"]\s*:\s*['"]Microsoft\.DBforMySQL\/flexibleServers['"]/gi,
    engine: 'mysql',
    deployment: 'azure-mysql-flexible-server',
    signature: 'resource.azure-arm.mysql-flexible-server',
    versionPattern: /['"]version['"]\s*:\s*['"]([0-9][0-9A-Za-z._+-]*)['"]/,
  },
  {
    pattern:
      /['"]type['"]\s*:\s*['"]Microsoft\.Cache\/redis['"]/gi,
    engine: 'redis',
    deployment: 'azure-cache-for-redis',
    signature: 'resource.azure-arm.redis',
  },
  {
    pattern:
      /['"]type['"]\s*:\s*['"]Microsoft\.Cache\/redisEnterprise['"]/gi,
    engine: 'redis',
    deployment: 'azure-managed-redis',
    signature: 'resource.azure-arm.redis-enterprise',
  },
  {
    pattern: /\bresource\s+['"]aws_db_instance['"]\s+['"]([^'"]+)['"]/g,
    engine: null,
    deployment: 'aws-rds',
    signature: 'resource.aws.rds-instance',
    enginePattern:
      /\bengine\s*=\s*['"](postgres|mysql|mariadb|oracle-[^'"]+|sqlserver-[^'"]+)['"]/i,
    versionPattern: /\bengine_version\s*=\s*['"]([0-9][0-9A-Za-z._+-]*)['"]/,
  },
  {
    pattern: /\bresource\s+['"]aws_rds_cluster['"]\s+['"]([^'"]+)['"]/g,
    engine: null,
    deployment: 'aws-rds-cluster',
    signature: 'resource.aws.rds-cluster',
    enginePattern:
      /\bengine\s*=\s*['"](aurora-postgresql|aurora-mysql|postgres|mysql)['"]/i,
    versionPattern: /\bengine_version\s*=\s*['"]([0-9][0-9A-Za-z._+-]*)['"]/,
  },
  {
    pattern: /\bresource\s+['"]aws_dynamodb_table['"]\s+['"]([^'"]+)['"]/g,
    engine: 'dynamodb',
    deployment: 'aws',
    signature: 'resource.aws.dynamodb',
  },
  {
    pattern:
      /\bresource\s+['"]aws_(?:elasticache_cluster|elasticache_replication_group)['"]\s+['"]([^'"]+)['"]/g,
    engine: 'redis',
    deployment: 'aws-elasticache',
    signature: 'resource.aws.elasticache',
  },
  {
    pattern:
      /\bresource\s+['"]aws_opensearch_domain['"]\s+['"]([^'"]+)['"]/g,
    engine: 'opensearch',
    deployment: 'aws',
    signature: 'resource.aws.opensearch',
  },
  {
    pattern: /\bresource\s+['"]aws_redshift_cluster['"]\s+['"]([^'"]+)['"]/g,
    engine: 'redshift',
    deployment: 'aws',
    signature: 'resource.aws.redshift',
  },
  {
    pattern:
      /^[ \t]{0,16}([A-Za-z][A-Za-z0-9]*)\s*:\s*\r?\n[ \t]+Type\s*:\s*['"]?AWS::RDS::DBInstance['"]?/gm,
    engine: null,
    deployment: 'aws-rds',
    signature: 'resource.aws-cloudformation.rds-instance',
    enginePattern:
      /\bEngine\s*:\s*['"]?(postgres|mysql|mariadb|oracle-[^'"\s]+|sqlserver-[^'"\s]+)['"]?/i,
    versionPattern: /\bEngineVersion\s*:\s*['"]?([0-9][0-9A-Za-z._+-]*)['"]?/,
  },
  {
    pattern:
      /^[ \t]{0,16}([A-Za-z][A-Za-z0-9]*)\s*:\s*\r?\n[ \t]+Type\s*:\s*['"]?AWS::DynamoDB::Table['"]?/gm,
    engine: 'dynamodb',
    deployment: 'aws',
    signature: 'resource.aws-cloudformation.dynamodb',
  },
  {
    pattern:
      /^[ \t]{0,16}([A-Za-z][A-Za-z0-9]*)\s*:\s*\r?\n[ \t]+Type\s*:\s*['"]?AWS::ElastiCache::(?:CacheCluster|ReplicationGroup)['"]?/gm,
    engine: 'redis',
    deployment: 'aws-elasticache',
    signature: 'resource.aws-cloudformation.elasticache',
  },
  {
    pattern:
      /^[ \t]{0,16}([A-Za-z][A-Za-z0-9]*)\s*:\s*\r?\n[ \t]+Type\s*:\s*['"]?AWS::OpenSearchService::Domain['"]?/gm,
    engine: 'opensearch',
    deployment: 'aws',
    signature: 'resource.aws-cloudformation.opensearch',
  },
  {
    pattern:
      /\bresource\s+['"]google_sql_database_instance['"]\s+['"]([^'"]+)['"]/g,
    engine: null,
    deployment: 'google-cloud-sql',
    signature: 'resource.gcp.cloud-sql',
    enginePattern:
      /\bdatabase_version\s*=\s*['"](POSTGRES|MYSQL|SQLSERVER)(?:_[A-Za-z0-9_]+)?['"]/i,
    versionPattern: /\bdatabase_version\s*=\s*['"]([A-Za-z0-9._+-]+)['"]/,
  },
  {
    pattern: /\bresource\s+['"]google_firestore_database['"]\s+['"]([^'"]+)['"]/g,
    engine: 'firestore',
    deployment: 'google-cloud',
    signature: 'resource.gcp.firestore',
  },
  {
    pattern: /\bresource\s+['"]google_bigquery_dataset['"]\s+['"]([^'"]+)['"]/g,
    engine: 'bigquery',
    deployment: 'google-cloud',
    signature: 'resource.gcp.bigquery',
  },
  {
    pattern: /\bresource\s+['"]google_redis_instance['"]\s+['"]([^'"]+)['"]/g,
    engine: 'redis',
    deployment: 'google-cloud-memorystore',
    signature: 'resource.gcp.redis',
  },
  {
    pattern:
      /\b(?:image\s*:\s*|image\s*=\s*['"])(postgres|mysql|mariadb|mongo(?:db)?|redis|valkey|cassandra|neo4j)(?::([0-9][0-9A-Za-z._+-]*))?/g,
    engineGroup: 1,
    versionGroup: 2,
    deployment: 'container',
    signature: 'resource.container.database-image',
  },
  {
    pattern: /\[\[d1_databases\]\]/g,
    engine: 'sqlite',
    deployment: 'cloudflare-d1',
    signature: 'resource.cloudflare.d1',
  },
  {
    pattern: /\bapiVersion\s*:\s*postgresql\.cnpg\.io\/[A-Za-z0-9.-]+/g,
    engine: 'postgresql',
    deployment: 'cloudnative-pg',
    signature: 'resource.kubernetes.cloudnative-pg',
  },
  {
    pattern: /\bapiVersion\s*:\s*psmdb\.percona\.com\/[A-Za-z0-9.-]+/g,
    engine: 'mongodb',
    deployment: 'percona-mongodb-operator',
    signature: 'resource.kubernetes.percona-mongodb',
  },
  {
    pattern: /\bapiVersion\s*:\s*redis\.redis\.opstreelabs\.in\/[A-Za-z0-9.-]+/g,
    engine: 'redis',
    deployment: 'redis-operator',
    signature: 'resource.kubernetes.redis-operator',
  },
])

const ARTIFACT_SIGNATURES = Object.freeze([
  {
    subtype: 'query-path',
    pattern:
      /\b(?:SELECT|INSERT\s+INTO|UPDATE\s+[A-Za-z_"][A-Za-z0-9_"]*|DELETE\s+FROM|MERGE\s+INTO)\b|\b(?:pool|db|database|connection|conn|repository)\s*\.\s*(?:query|execute)\s*\(/i,
    signature: 'artifact.query-path',
  },
  {
    subtype: 'query-path',
    pattern:
      /\.\s*(?:find|findOne|aggregate|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|bulkWrite|watch)\s*\(/i,
    guardPattern: /\b(?:MongoClient|mongoose|pymongo|motor|mongodb)\b/i,
    engine: 'mongodb',
    signature: 'artifact.query.mongodb',
  },
  {
    subtype: 'query-path',
    pattern:
      /\.\s*(?:get|set|mget|mset|hget|hset|xread|xadd|eval|multi|pipeline)\s*\(/i,
    guardPattern:
      /\b(?:createClient|ioredis|Redis|redisClient|upstash|StackExchange\.Redis|go-redis)\b/i,
    engine: 'redis',
    signature: 'artifact.query.redis',
  },
  {
    subtype: 'query-path',
    pattern:
      /\b(?:GetItem|PutItem|UpdateItem|DeleteItem|Query|Scan|BatchGet|BatchWrite|TransactGet|TransactWrite)Command\b|\.\s*(?:getItem|putItem|updateItem|deleteItem|batchGetItem|batchWriteItem)\s*\(/i,
    guardPattern: /\b(?:DynamoDB|dynamodb)\b/,
    engine: 'dynamodb',
    signature: 'artifact.query.dynamodb',
  },
  {
    subtype: 'query-path',
    pattern:
      /\.\s*(?:collection|collectionGroup|doc|where|runTransaction|onSnapshot)\s*\(/i,
    guardPattern:
      /\b(?:getFirestore|firebase-admin|@google-cloud\/firestore|Firestore)\b/i,
    engine: 'firestore',
    signature: 'artifact.query.firestore',
  },
  {
    subtype: 'query-path',
    pattern:
      /\.\s*(?:search|msearch|index|bulk|mget|updateByQuery|deleteByQuery)\s*\(/i,
    guardPattern:
      /\b(?:@elastic\/elasticsearch|Elasticsearch|elastic(?:search)?Client)\b/i,
    engine: 'elasticsearch',
    signature: 'artifact.query.elasticsearch',
  },
  {
    subtype: 'query-path',
    pattern:
      /\.\s*(?:search|msearch|index|bulk|mget|updateByQuery|deleteByQuery)\s*\(/i,
    guardPattern:
      /\b(?:@opensearch-project\/opensearch|opensearchpy|OpenSearch)\b/i,
    engine: 'opensearch',
    signature: 'artifact.query.opensearch',
  },
  {
    subtype: 'query-path',
    pattern:
      /\b(?:MATCH|OPTIONAL\s+MATCH|MERGE|UNWIND)\s*\([^)]*\)|\bsession\s*\.\s*run\s*\(/i,
    guardPattern: /\b(?:neo4j|GraphDatabase|session\s*\.\s*run)\b/i,
    engine: 'neo4j',
    signature: 'artifact.query.neo4j',
  },
  {
    subtype: 'query-path',
    pattern:
      /\b(?:SELECT|INSERT|UPDATE|DELETE)\b|\.\s*execute\s*\(/i,
    guardPattern: /\b(?:cassandra-driver|cassandra\.cluster|Cassandra|keyspace)\b/i,
    engine: 'cassandra',
    signature: 'artifact.query.cassandra',
  },
  {
    subtype: 'query-path',
    pattern: /\.\s*(?:query|createQueryJob)\s*\(/i,
    guardPattern: /\b(?:@google-cloud\/bigquery|BigQuery)\b/i,
    engine: 'bigquery',
    signature: 'artifact.query.bigquery',
  },
  {
    subtype: 'query-path',
    pattern: /\b(?:sqlText|execute\s*\(\s*\{)\b/i,
    guardPattern: /\b(?:snowflake-sdk|snowflake\.connector|snowflake)\b/i,
    engine: 'snowflake',
    signature: 'artifact.query.snowflake',
  },
  {
    subtype: 'query-path',
    pattern: /\.\s*(?:query|upsert|fetch|deleteMany)\s*\(/i,
    guardPattern: /\b(?:Pinecone|pinecone)\b/,
    engine: 'pinecone',
    signature: 'artifact.query.pinecone',
  },
  {
    subtype: 'query-path',
    pattern: /\.\s*(?:search|query|scroll|upsert|recommend)\s*\(/i,
    guardPattern: /\b(?:QdrantClient|qdrant)\b/i,
    engine: 'qdrant',
    signature: 'artifact.query.qdrant',
  },
  {
    subtype: 'query-path',
    pattern:
      /\.\s*(?:nearText|nearVector|hybrid|withWhere|insertMany|query)\s*\(/i,
    guardPattern: /\b(?:weaviate|WeaviateClient)\b/i,
    engine: 'weaviate',
    signature: 'artifact.query.weaviate',
  },
  {
    subtype: 'schema-or-migration',
    pattern:
      /\b(?:CREATE|ALTER|DROP)\s+(?:TABLE|COLLECTION|INDEX|VIEW|SCHEMA)\b|\b(?:up|down)\s*\(\s*(?:knex|queryRunner)\b/i,
    pathPattern: /(?:^|\/)(?:migrations?|schema)(?:\/|\.|$)/i,
    signature: 'artifact.schema-or-migration',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\bdb\s*\.\s*(?:createUser|updateUser|grantRolesToUser|createRole|updateRole|grantPrivilegesToRole)\s*\(/i,
    engine: 'mongodb',
    signature: 'artifact.security.mongodb-role',
  },
  {
    subtype: 'principal-or-grant',
    pattern: /\bACL\s+(?:SETUSER|DELUSER|CAT|LIST|WHOAMI)\b/i,
    engine: 'redis',
    signature: 'artifact.security.redis-acl',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\bdynamodb:(?:GetItem|PutItem|UpdateItem|DeleteItem|Query|Scan|BatchGetItem|BatchWriteItem|TransactGetItems|TransactWriteItems)\b/i,
    engine: 'dynamodb',
    signature: 'artifact.security.dynamodb-iam',
  },
  {
    subtype: 'row-authorization-policy',
    pattern: /\bdynamodb:LeadingKeys\b/i,
    engine: 'dynamodb',
    signature: 'artifact.security.dynamodb-leading-keys',
  },
  {
    subtype: 'row-authorization-policy',
    pattern:
      /\bmatch\s+\/databases\/\{[^}]+\}\/documents\b|\ballow\s+(?:read|write|create|update|delete)\s*:/i,
    guardPattern: /\b(?:firestore|request\.auth|resource\.data)\b/i,
    engine: 'firestore',
    signature: 'artifact.security.firestore-rules',
  },
  {
    subtype: 'principal-or-grant',
    pattern: /\b(?:xpack\.security|_security\/role|roles\.yml)\b/i,
    engine: 'elasticsearch',
    signature: 'artifact.security.elasticsearch-role',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\b(?:plugins\.security|_plugins\/_security|aoss:(?:ReadDocument|WriteDocument|CreateIndex))\b/i,
    engine: 'opensearch',
    signature: 'artifact.security.opensearch-role',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\b(?:GRANT|DENY|REVOKE)\s+(?:TRAVERSE|MATCH|READ|WRITE|ACCESS|EXECUTE)\b(?=[^;\r\n]{0,160}\bON\s+(?:GRAPH|DBMS)\b)/i,
    engine: 'neo4j',
    signature: 'artifact.security.neo4j-privilege',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\b(?:CREATE|ALTER)\s+ROLE\b|\b(?:GRANT|REVOKE)\s+(?:SELECT|MODIFY|AUTHORIZE|DESCRIBE|EXECUTE|ALL)\b/i,
    guardPattern: /\b(?:Cassandra|cassandra|keyspace|authenticator|authorizer)\b/i,
    engine: 'cassandra',
    signature: 'artifact.security.cassandra-role',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\b(?:roles\/bigquery\.[A-Za-z]+|bigquery\.datasets\.(?:get|update)|bigquery\.tables\.(?:get|create|getData|updateData))\b/i,
    engine: 'bigquery',
    signature: 'artifact.security.bigquery-iam',
  },
  {
    subtype: 'row-authorization-policy',
    pattern:
      /\b(?:CREATE|ALTER|DROP)\s+ROW\s+ACCESS\s+POLICY\b|\bFILTER\s+USING\b/i,
    guardPattern: /\b(?:bigquery|ROW\s+ACCESS\s+POLICY)\b/i,
    engine: 'bigquery',
    signature: 'artifact.security.bigquery-row-access-policy',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\b(?:GRANT|REVOKE)\s+(?:USAGE|SELECT|INSERT|UPDATE|DELETE|CREATE|MONITOR|OWNERSHIP)\b/i,
    guardPattern: /\b(?:snowflake|WAREHOUSE|DATABASE\s+ROLE)\b/i,
    engine: 'snowflake',
    signature: 'artifact.security.snowflake-role',
  },
  {
    subtype: 'row-authorization-policy',
    pattern:
      /\b(?:CREATE|ALTER|DROP)\s+(?:ROW\s+ACCESS|MASKING)\s+POLICY\b/i,
    engine: 'snowflake',
    signature: 'artifact.security.snowflake-policy',
  },
  {
    subtype: 'cdc',
    pattern: /\b(?:changeStream|change[_ -]?stream|\.watch\s*\()\b/i,
    guardPattern: /\b(?:MongoClient|mongodb|pymongo|mongoose)\b/i,
    engine: 'mongodb',
    signature: 'copy.mongodb-change-stream',
  },
  {
    subtype: 'backup',
    pattern: /\b(?:mongodump|mongorestore|continuous[_ -]?backup)\b/i,
    engine: 'mongodb',
    signature: 'copy.mongodb-backup',
  },
  {
    subtype: 'replica',
    pattern: /\b(?:replicaof|slaveof|masterauth|sentinel\s+monitor)\b/i,
    engine: 'redis',
    signature: 'copy.redis-replica',
  },
  {
    subtype: 'backup',
    pattern:
      /(?:\b(?:BGSAVE|SAVE)\b|\b(?:appendonly|appendfsync|dbfilename)\b)/,
    engine: 'redis',
    signature: 'copy.redis-persistence',
  },
  {
    subtype: 'cdc',
    pattern: /\b(?:StreamEnabled|StreamViewType|DynamoDBStreams|stream_arn)\b/i,
    engine: 'dynamodb',
    signature: 'copy.dynamodb-stream',
  },
  {
    subtype: 'backup',
    pattern:
      /\b(?:point_in_time_recovery|PointInTimeRecoveryEnabled|CreateBackup)\b/i,
    engine: 'dynamodb',
    signature: 'copy.dynamodb-backup',
  },
  {
    subtype: 'export',
    pattern: /\bExportTableToPointInTime\b/i,
    engine: 'dynamodb',
    signature: 'copy.dynamodb-export',
  },
  {
    subtype: 'export',
    pattern: /\b(?:gcloud\s+firestore\s+export|exportDocuments)\b/i,
    guardPattern: /\b(?:firestore|exportDocuments)\b/i,
    engine: 'firestore',
    signature: 'copy.firestore-export',
  },
  {
    subtype: 'backup',
    pattern:
      /\b(?:_snapshot\/|snapshot\.repository|slm\.policy|CreateSnapshot)\b/i,
    guardPattern: /\b(?:elasticsearch|xpack|_snapshot)\b/i,
    engine: 'elasticsearch',
    signature: 'copy.elasticsearch-snapshot',
  },
  {
    subtype: 'backup',
    pattern:
      /\b(?:_snapshot\/|snapshot\.repository|CreateSnapshot)\b/i,
    guardPattern: /\b(?:opensearch|_plugins|aoss|_snapshot)\b/i,
    engine: 'opensearch',
    signature: 'copy.opensearch-snapshot',
  },
  {
    subtype: 'backup',
    pattern: /\b(?:neo4j-admin\s+(?:database\s+)?(?:backup|dump)|online_backup)\b/i,
    engine: 'neo4j',
    signature: 'copy.neo4j-backup',
  },
  {
    subtype: 'replica',
    pattern:
      /\b(?:NetworkTopologyStrategy|SimpleStrategy|replication_factor)\b/i,
    engine: 'cassandra',
    signature: 'copy.cassandra-replication',
  },
  {
    subtype: 'backup',
    pattern: /\b(?:nodetool\s+snapshot|sstableloader|commitlog_archiving)\b/i,
    engine: 'cassandra',
    signature: 'copy.cassandra-snapshot',
  },
  {
    subtype: 'export',
    pattern: /\b(?:EXPORT\s+DATA|extract_job|createExtractJob)\b/i,
    engine: 'bigquery',
    signature: 'copy.bigquery-export',
  },
  {
    subtype: 'export',
    pattern:
      /\b(?:COPY\s+INTO\s+@|CREATE\s+(?:DATABASE|SCHEMA|TABLE)\s+.+\s+CLONE\b|UNLOAD\s*\()\b/i,
    engine: 'snowflake',
    signature: 'copy.snowflake-export-or-clone',
  },
  {
    subtype: 'backup',
    pattern: /\b(?:createSnapshot|snapshot_collection|backupCRON)\b/i,
    guardPattern: /\b(?:Pinecone|pinecone)\b/,
    engine: 'pinecone',
    signature: 'copy.pinecone-snapshot',
  },
  {
    subtype: 'backup',
    pattern: /\b(?:createSnapshot|snapshot_collection)\b/i,
    guardPattern: /\b(?:QdrantClient|qdrant)\b/i,
    engine: 'qdrant',
    signature: 'copy.qdrant-snapshot',
  },
  {
    subtype: 'backup',
    pattern: /\b(?:createSnapshot|backupCRON)\b/i,
    guardPattern: /\b(?:weaviate|WeaviateClient)\b/i,
    engine: 'weaviate',
    signature: 'copy.weaviate-backup',
  },
  {
    subtype: 'principal-or-grant',
    pattern:
      /\b(?:CREATE|ALTER|DROP)\s+(?:ROLE|USER)\b|\b(?:GRANT|REVOKE|DENY)\s+(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE|USAGE|ALL|CONNECT|CREATE|REFERENCES|MATCH|TRAVERSE|READ|WRITE)\b|\bACL\s+(?:SETUSER|DELUSER|CAT|LIST)\b|\b(?:relacl|nspacl|datacl|readWrite|dbAdmin|clusterAdmin|readAnyDatabase)\b|\b(?:dynamodb|firestore|es|aoss):(?:GetItem|PutItem|UpdateItem|DeleteItem|Query|Scan|BatchGetItem|BatchWriteItem)\b/i,
    signature: 'artifact.principal-or-grant',
  },
  {
    subtype: 'row-authorization-policy',
    pattern:
      /\b(?:CREATE|ALTER|DROP)\s+(?:SECURITY\s+)?POLICY\b|\bROW\s+LEVEL\s+SECURITY\b|\bFORCE\s+ROW\s+LEVEL\s+SECURITY\b|\b(?:BYPASSRLS|rolbypassrls|DBMS_RLS|dynamodb:LeadingKeys|document[_ -]?level[_ -]?security)\b|\ballow\s+(?:read|write)\s*:/i,
    signature: 'artifact.row-authorization-policy',
  },
  {
    subtype: 'execution-context',
    pattern:
      /\bSECURITY\s+(?:DEFINER|INVOKER)\b|\bSQL\s+SECURITY\b|\bAUTHID\s+(?:CURRENT_USER|DEFINER)\b|\bEXECUTE\s+AS\b|\bOWNER\s+TO\b|\bDEFINER\s*=/i,
    signature: 'artifact.execution-context',
  },
  {
    subtype: 'replica',
    pattern:
      /\b(?:read[_ -]?replicas?|replication|replicaCount|replicate_source_db|source_replica|secondaryPreferred)\b/i,
    signature: 'copy.replica',
  },
  {
    subtype: 'cdc',
    pattern:
      /\b(?:change[_ -]?data[_ -]?capture|logical[_ -]?replication|CREATE\s+PUBLICATION|change[_ -]?streams?|change[_ -]?tracking|debezium|binlog_format|wal_level|cdc\.fn_cdc|DBMS_LOGMNR|GoldenGate|stream_enabled|StreamViewType)\b/i,
    signature: 'copy.cdc',
  },
  {
    subtype: 'backup',
    pattern:
      /\b(?:BACKUP\s+DATABASE|RESTORE\s+DATABASE|pg_dump|pg_restore|mysqldump|mongodump|snapshotRetention|backupRetention|backup_retention_period|geoRedundantBackup|pointInTimeRestore|point_in_time_recovery|continuous[_ -]?backup|final_snapshot)\b/i,
    signature: 'copy.backup',
  },
  {
    subtype: 'export',
    pattern:
      /\b(?:COPY\s+.+\s+TO|INTO\s+OUTFILE|EXPORT\s+DATA|mongoexport|data[_ -]?export|exportDocuments|EXPORT_TO_S3|UNLOAD\s*\(|extract_job)\b/i,
    signature: 'copy.export',
  },
  {
    subtype: 'cache',
    pattern:
      /\b(?:(?:query|database|db|result)[_ -]?cache|cache[_ -]?aside|second[_ -]?level[_ -]?cache|materialized\s+view|ElastiCache|Memorystore|(?:Redis|Valkey)[_ -]?cache)\b/i,
    signature: 'copy.cache',
  },
])

const URI_ENGINES = Object.freeze({
  postgres: 'postgresql',
  postgresql: 'postgresql',
  mysql: 'mysql',
  mariadb: 'mariadb',
  mongodb: 'mongodb',
  'mongodb+srv': 'mongodb',
  redis: 'redis',
  rediss: 'redis',
  sqlserver: 'sqlserver',
  oracle: 'oracle',
  cassandra: 'cassandra',
  neo4j: 'neo4j',
  snowflake: 'snowflake',
})

const BINDING_TOKEN_PATTERN =
  /\b(?:DATABASE_URL|DATABASE_URI|DATABASE_DSN|DB_URL|DB_URI|DB_DSN|JDBC_URL|SQLALCHEMY_DATABASE_URI|CONNECTION_STRING|POSTGRES(?:QL)?_(?:URL|URI|DSN|HOST|PORT|DATABASE|DB|USER|USERNAME|PASSWORD)|PG(?:URL|URI|DSN|HOST|PORT|DATABASE|USER|PASSWORD)|MYSQL_(?:URL|URI|DSN|HOST|PORT|DATABASE|DB|USER|PASSWORD)|MARIADB_(?:URL|URI|DSN|HOST|PORT|DATABASE|DB|USER|PASSWORD)|MONGO(?:DB)?_(?:URL|URI|HOST|DATABASE|DB|USER|PASSWORD)|REDIS_(?:URL|URI|HOST|PORT|USER|PASSWORD)|SQLSERVER_(?:URL|URI|HOST|PORT|DATABASE|DB|USER|PASSWORD)|ORACLE_(?:URL|URI|HOST|PORT|SERVICE|USER|PASSWORD)|DYNAMODB_(?:ENDPOINT|TABLE|REGION)|FIRESTORE_(?:PROJECT|DATABASE)|ELASTICSEARCH_(?:URL|URI|ENDPOINT|HOST|USER|USERNAME|PASSWORD|API_KEY)|OPENSEARCH_(?:URL|URI|ENDPOINT|HOST|USER|USERNAME|PASSWORD|API_KEY)|NEO4J_(?:URL|URI|HOST|DATABASE|USER|USERNAME|PASSWORD)|CASSANDRA_(?:URL|URI|HOST|HOSTS|PORT|KEYSPACE|USER|USERNAME|PASSWORD)|BIGQUERY_(?:PROJECT|DATASET|LOCATION|CREDENTIALS)|SNOWFLAKE_(?:ACCOUNT|DATABASE|WAREHOUSE|USER|PASSWORD)|PINECONE_(?:HOST|INDEX|ENVIRONMENT|API_KEY)|QDRANT_(?:URL|URI|HOST|PORT|COLLECTION|API_KEY)|WEAVIATE_(?:URL|URI|HOST|CLASS|API_KEY)|SUPABASE_(?:URL|SERVICE_ROLE_KEY|ANON_KEY)|NEON_(?:DATABASE_)?(?:URL|URI)|TURSO_(?:DATABASE_)?(?:URL|URI|AUTH_TOKEN)|PLANETSCALE_(?:DATABASE_)?(?:URL|URI)|UPSTASH_REDIS_(?:REST_URL|REST_TOKEN|URL))\b/g

const CAMEL_BINDING_PATTERN =
  /\b(databaseUrl|databaseUri|databaseDsn|dbUrl|dbUri|connectionString|postgresUrl|postgresUri|mongoUrl|mongoUri|redisUrl|jdbcUrl)\b/g

class UnionFind {
  constructor(values) {
    this.parent = new Map(values.map((value) => [value, value]))
  }

  find(value) {
    let root = this.parent.get(value)
    if (root === undefined) return null
    while (root !== this.parent.get(root)) root = this.parent.get(root)
    let current = value
    while (current !== root) {
      const next = this.parent.get(current)
      this.parent.set(current, root)
      current = next
    }
    return root
  }

  union(left, right) {
    const leftRoot = this.find(left)
    const rightRoot = this.find(right)
    if (leftRoot === null || rightRoot === null || leftRoot === rightRoot) return
    const [first, second] = [leftRoot, rightRoot].sort()
    this.parent.set(second, first)
  }
}

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null)
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableId(prefix, ...parts) {
  return `${prefix}-${sha256(parts.join('\0')).slice(0, 20)}`
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (!isPlainObject(value)) return value
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
  )
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value))
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value))
}

function normalizeRepositoryPath(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 16_384
  ) return null
  if (
    /[\0\r\n\\]/.test(value)
    || /^[A-Za-z]:/.test(value)
    || value.startsWith('/')
  ) return null
  const segments = value.split('/')
  if (segments.some((segment) =>
    segment.length === 0
    || segment === '.'
    || segment === '..')) return null
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return null
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return null
    }
  }
  // Inventory paths are controller-owned canonical identities. Validate them;
  // never trim, case-fold, normalize Unicode, or reinterpret separators.
  return value
}

let cachedLineText = null
let cachedLineStarts = [0]

function lineNumberAt(text, index) {
  if (text !== cachedLineText) {
    cachedLineText = text
    cachedLineStarts = [0]
    for (let cursor = 0; cursor < text.length; cursor += 1) {
      if (text.charCodeAt(cursor) === 10) cachedLineStarts.push(cursor + 1)
    }
  }
  let low = 0
  let high = cachedLineStarts.length
  while (low < high) {
    const middle = Math.floor((low + high) / 2)
    if (cachedLineStarts[middle] <= index) low = middle + 1
    else high = middle
  }
  return Math.max(1, low)
}

function uniqueSorted(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined))]
    .sort(compareCanonicalStrings)
}

function compareText(left, right) {
  return compareCanonicalStrings(left, right)
}

function contextClassifications(repositoryPath) {
  const lower = repositoryPath.toLowerCase()
  const segments = lower.split('/')
  const file = segments.at(-1)
  const classes = []
  if (
    segments.some((segment) => ['docs', 'documentation'].includes(segment))
    || /^(?:readme|changelog|contributing)(?:\.|$)/.test(file)
    || /^security(?:$|\.(?:md|rst|adoc|txt))$/.test(file)
    || /\.(?:md|mdx|rst|adoc)$/.test(file)
    || /(?:^|\.)(?:example|sample|template)(?:\.|$)/.test(file)
  ) {
    classes.push('documentation')
  }
  if (
    segments.some((segment) =>
      ['test', 'tests', '__tests__', 'fixtures', 'samples', '__fixtures__'].includes(segment))
    || /\.(?:test|spec)\.[^.]+$/.test(file)
  ) {
    classes.push('test-or-fixture')
  }
  if (
    segments.some((segment) =>
      ['dist', 'build', 'generated', 'vendor', 'coverage', '.next'].includes(segment))
    || /\.(?:min\.js|map)$/.test(file)
    || /^(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|cargo\.lock)$/.test(file)
  ) {
    classes.push('generated-or-vendored')
  }
  return uniqueSorted(classes)
}

function normalizeLimits(options) {
  const read = (camel, snake, fallback, minimum, maximum) => {
    const raw = options?.[camel] ?? options?.[snake]
    if (raw === undefined) return fallback
    if (!Number.isSafeInteger(raw) || raw < minimum || raw > maximum) {
      throw new RangeError(
        `${camel} must be a safe integer between ${minimum} and ${maximum}`,
      )
    }
    return raw
  }
  return Object.freeze({
    max_nodes: read(
      'maxNodes',
      'max_nodes',
      DEFAULT_LIMITS.max_nodes,
      1,
      HARD_LIMITS.max_nodes,
    ),
    max_edges: read(
      'maxEdges',
      'max_edges',
      DEFAULT_LIMITS.max_edges,
      1,
      HARD_LIMITS.max_edges,
    ),
    max_rounds: read(
      'maxRounds',
      'max_rounds',
      DEFAULT_LIMITS.max_rounds,
      1,
      HARD_LIMITS.max_rounds,
    ),
    max_token_fanout: read(
      'maxTokenFanout',
      'max_token_fanout',
      DEFAULT_LIMITS.max_token_fanout,
      2,
      HARD_LIMITS.max_token_fanout,
    ),
  })
}

function inventoryEntries(inventory) {
  if (Array.isArray(inventory)) return inventory
  if (isPlainObject(inventory) && Array.isArray(inventory.entries)) return inventory.entries
  if (isPlainObject(inventory) && Array.isArray(inventory.files)) return inventory.files
  throw new TypeError('database discovery inventory must be an array or contain entries/files')
}

function normalizeInventory(inventory) {
  const sourceEntries = inventoryEntries(inventory)
  if (sourceEntries.length > HARD_LIMITS.max_inventory_entries) {
    throw new RangeError(
      `database discovery inventory must contain at most ${
        HARD_LIMITS.max_inventory_entries
      } entries`,
    )
  }

  let totalTextBytes = 0
  for (const [index, entry] of sourceEntries.entries()) {
    if (!isPlainObject(entry) || typeof entry.content !== 'string') continue
    const textBytes = Buffer.byteLength(entry.content)
    if (textBytes > HARD_LIMITS.max_single_text_bytes) {
      throw new RangeError(
        `database discovery inventory entry ${index} content exceeds ${
          HARD_LIMITS.max_single_text_bytes
        } bytes`,
      )
    }
    totalTextBytes += textBytes
    if (totalTextBytes > HARD_LIMITS.max_text_bytes) {
      throw new RangeError(
        `database discovery inventory text exceeds ${
          HARD_LIMITS.max_text_bytes
        } bytes`,
      )
    }
  }

  const rejected = []
  const candidates = []
  for (const [index, entry] of sourceEntries.entries()) {
    if (!isPlainObject(entry)) {
      rejected.push({ index, reason: 'inventory-entry-not-an-object' })
      continue
    }
    const repositoryPath = normalizeRepositoryPath(entry.path)
    if (!repositoryPath) {
      rejected.push({ index, reason: 'inventory-entry-path-not-repository-relative' })
      continue
    }
    const content = typeof entry.content === 'string' ? entry.content : null
    const kind = typeof entry.kind === 'string'
      ? entry.kind.toLowerCase()
      : content === null ? 'unknown' : 'text'
    const size = Number.isSafeInteger(entry.size) && entry.size >= 0
      ? entry.size
      : content === null ? 0 : Buffer.byteLength(content)
    candidates.push({
      path: repositoryPath,
      kind,
      size,
      content,
      context: contextClassifications(repositoryPath),
      deterministicTieBreak: sha256(`${kind}\0${size}\0${content ?? ''}`),
    })
  }
  candidates.sort((left, right) =>
    compareText(left.path, right.path)
      || compareText(left.deterministicTieBreak, right.deterministicTieBreak))

  const entries = []
  const duplicates = []
  for (const candidate of candidates) {
    if (entries.at(-1)?.path === candidate.path) {
      duplicates.push(candidate.path)
      continue
    }
    const { deterministicTieBreak: _ignored, ...entry } = candidate
    entries.push(entry)
  }
  return { entries, rejected, duplicates: uniqueSorted(duplicates) }
}

function componentRoots(entries) {
  return uniqueSorted(
    entries
      .filter((entry) => {
        const name = posix.basename(entry.path).toLowerCase()
        return MANIFEST_NAMES.has(name) || /\.csproj$/i.test(name)
      })
      .map((entry) => {
        const directory = posix.dirname(entry.path)
        return directory === '' ? '.' : directory
      }),
  )
}

function componentRootFor(repositoryPath, roots) {
  const matching = roots
    .filter((root) =>
      root === '.' || repositoryPath === root || repositoryPath.startsWith(`${root}/`))
    .sort((left, right) => right.length - left.length || compareText(left, right))
  if (matching.length > 0) return matching[0]
  const first = repositoryPath.split('/')[0]
  return repositoryPath.includes('/') ? first : '.'
}

function projectGroupFor(repositoryPath, roots) {
  return componentRootFor(repositoryPath, roots)
}

function canonicalToken(value) {
  return value
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase()
}

function engineForToken(token) {
  if (/^(?:POSTGRES|POSTGRESQL|PG)_/.test(token)) return 'postgresql'
  if (/^(?:SUPABASE|NEON)_/.test(token)) return 'postgresql'
  if (/^MYSQL_/.test(token)) return 'mysql'
  if (/^PLANETSCALE_/.test(token)) return 'mysql'
  if (/^MARIADB_/.test(token)) return 'mariadb'
  if (/^MONGO(?:DB)?_/.test(token)) return 'mongodb'
  if (/^REDIS_/.test(token)) return 'redis'
  if (/^UPSTASH_REDIS_/.test(token)) return 'redis'
  if (/^TURSO_/.test(token)) return 'sqlite'
  if (/^SQLSERVER_/.test(token)) return 'sqlserver'
  if (/^ORACLE_/.test(token)) return 'oracle'
  if (/^DYNAMODB_/.test(token)) return 'dynamodb'
  if (/^FIRESTORE_/.test(token)) return 'firestore'
  if (/^ELASTICSEARCH_/.test(token)) return 'elasticsearch'
  if (/^OPENSEARCH_/.test(token)) return 'opensearch'
  if (/^NEO4J_/.test(token)) return 'neo4j'
  if (/^CASSANDRA_/.test(token)) return 'cassandra'
  if (/^BIGQUERY_/.test(token)) return 'bigquery'
  if (/^SNOWFLAKE_/.test(token)) return 'snowflake'
  if (/^PINECONE_/.test(token)) return 'pinecone'
  if (/^QDRANT_/.test(token)) return 'qdrant'
  if (/^WEAVIATE_/.test(token)) return 'weaviate'
  return null
}

function bindingRole(token) {
  return /(?:PASSWORD|SECRET|TOKEN|KEY)$/.test(token)
    ? 'credential'
    : /(?:URL|URI|DSN|HOST|ENDPOINT|CONNECTION_STRING|JDBC_URL)$/.test(token)
      ? 'endpoint'
      : 'configuration'
}

function isStrongDatabaseToken(token) {
  return /(?:DATABASE|POSTGRES|POSTGRESQL|MYSQL|MARIADB|MONGO|REDIS|SQLSERVER|ORACLE|DYNAMODB|FIRESTORE|ELASTICSEARCH|OPENSEARCH|NEO4J|CASSANDRA|BIGQUERY|SNOWFLAKE|PINECONE|QDRANT|WEAVIATE|SUPABASE|NEON|TURSO|PLANETSCALE|UPSTASH|JDBC|CONNECTION)/.test(token)
    && /(?:URL|URI|DSN|HOST|HOSTS|PORT|DATABASE|DB|USER|USERNAME|PASSWORD|SERVICE|ENDPOINT|TABLE|PROJECT|DATASET|LOCATION|ACCOUNT|WAREHOUSE|INDEX|ENVIRONMENT|COLLECTION|CLASS|CREDENTIALS|STRING|SERVER|KEY|TOKEN|REGION|KEYSPACE)$/.test(token)
}

function evidence(repositoryPath, line, signatureId, strength = 'strong') {
  return {
    path: repositoryPath,
    line,
    signature_id: signatureId,
    strength,
  }
}

function addObservation(map, observation) {
  const key = [
    observation.kind,
    observation.subtype,
    observation.signatureId,
    observation.token ?? '',
    observation.symbol ?? '',
    ...(observation.engines ?? []),
  ].join('\0')
  const prior = map.get(key)
  if (!prior) {
    map.set(key, {
      ...observation,
      engines: uniqueSorted(observation.engines ?? []),
      deployments: uniqueSorted(observation.deployments ?? []),
      versions: uniqueSorted(observation.versions ?? []),
      evidence: [observation.evidence],
    })
    return
  }
  prior.engines = uniqueSorted([...prior.engines, ...(observation.engines ?? [])])
  prior.deployments = uniqueSorted([...prior.deployments, ...(observation.deployments ?? [])])
  prior.versions = uniqueSorted([...prior.versions, ...(observation.versions ?? [])])
  const evidenceKey = canonicalJson(observation.evidence)
  if (!prior.evidence.some((item) => canonicalJson(item) === evidenceKey)) {
    prior.evidence.push(observation.evidence)
  }
}

function scanPackageJson(entry, observations, gaps) {
  if (posix.basename(entry.path).toLowerCase() !== 'package.json') return
  let parsed
  try {
    parsed = JSON.parse(entry.content.replace(/^\uFEFF/, ''))
  } catch {
    gaps.push({
      code: 'unparseable-manifest',
      subject: 'package.json',
      detail: `${
        stableId('source', entry.path)
      } is not valid JSON, so no manifest client evidence was read from it`,
    })
    return
  }
  for (const section of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'devDependencies',
  ]) {
    if (!isPlainObject(parsed[section])) continue
    for (const client of CLIENT_PACKAGES) {
      if (!Object.hasOwn(parsed[section], client.package)) continue
      const packageIndex = entry.content.indexOf(`"${client.package}"`)
      addObservation(observations, {
        kind: 'client',
        subtype: 'direct-dependency',
        signatureId: `${client.signature}.${section}`,
        engines: [client.engine],
        deployments: client.deployment ? [client.deployment] : [],
        versions: [],
        seedEligible: section !== 'devDependencies',
        evidence: evidence(
          entry.path,
          lineNumberAt(entry.content, Math.max(0, packageIndex)),
          `${client.signature}.${section}`,
          section === 'devDependencies' ? 'context' : 'strong',
        ),
      })
    }
  }
}

function scanOtherManifests(entry, observations) {
  const name = posix.basename(entry.path).toLowerCase()
  if (
    !MANIFEST_NAMES.has(name)
    && !/\.csproj$/i.test(name)
  ) return
  if (name === 'package.json') return

  const signatures = [
    {
      pattern:
        /\b(?:psycopg2|psycopg|asyncpg|npgsql|github\.com\/jackc\/pgx|github\.com\/lib\/pq|org\.postgresql|tokio-postgres|postgresql)\b/i,
      engine: 'postgresql',
      signature: 'client.manifest.postgresql',
    },
    {
      pattern:
        /\b(?:pymysql|mysql-connector|mysqlclient|go-sql-driver\/mysql|com\.mysql:mysql-connector|mysql2)\b/i,
      engine: 'mysql',
      signature: 'client.manifest.mysql',
    },
    {
      pattern: /\b(?:mariadb|org\.mariadb\.jdbc)\b/i,
      engine: 'mariadb',
      signature: 'client.manifest.mariadb',
    },
    {
      pattern:
        /\b(?:pymongo|mongodb\.driver|mongo-go-driver|go\.mongodb\.org\/mongo-driver|mongoid)\b/i,
      engine: 'mongodb',
      signature: 'client.manifest.mongodb',
    },
    {
      pattern:
        /(?:\b(?:StackExchange\.Redis|redis-py|go-redis|jedis|lettuce-core)\b|(?:^|\n)\s*redis(?:\[[^\]]+\])?\s*(?:[<>=~!]|$))/im,
      engine: 'redis',
      signature: 'client.manifest.redis',
    },
    {
      pattern:
        /\b(?:Microsoft\.Data\.SqlClient|System\.Data\.SqlClient|mssql-jdbc|go-mssqldb)\b/i,
      engine: 'sqlserver',
      signature: 'client.manifest.sqlserver',
    },
    {
      pattern: /\b(?:oracledb|ojdbc|godror)\b/i,
      engine: 'oracle',
      signature: 'client.manifest.oracle',
    },
    {
      pattern:
        /\b(?:sqlite|rusqlite|go-sqlite3|modernc\.org\/sqlite|Microsoft\.Data\.Sqlite)\b/i,
      engine: 'sqlite',
      signature: 'client.manifest.sqlite',
    },
    {
      pattern: /\b(?:snowflake-connector|snowflake-sdk|gosnowflake)\b/i,
      engine: 'snowflake',
      signature: 'client.manifest.snowflake',
    },
    {
      pattern: /\b(?:cassandra-driver|gocql|java-driver-core)\b/i,
      engine: 'cassandra',
      signature: 'client.manifest.cassandra',
    },
    {
      pattern: /\b(?:neo4j-driver|neo4j-java-driver)\b/i,
      engine: 'neo4j',
      signature: 'client.manifest.neo4j',
    },
    {
      pattern: /\b(?:elasticsearch|opensearch)\b/i,
      engine: null,
      signature: 'client.manifest.search-store',
    },
    {
      pattern:
        /\b(?:sqlalchemy|django|EntityFrameworkCore|hibernate-core|jooq|diesel|sqlx)\b/i,
      engine: null,
      signature: 'client.manifest.orm',
    },
  ]
  for (const signature of signatures) {
    const match = signature.pattern.exec(entry.content)
    if (!match) continue
    addObservation(observations, {
      kind: 'client',
      subtype: 'direct-dependency',
      signatureId: signature.signature,
      engines: [signature.engine],
      deployments: [],
      versions: [],
      evidence: evidence(
        entry.path,
        lineNumberAt(entry.content, match.index),
        signature.signature,
      ),
    })
  }
}

function scanSourceClients(entry, observations) {
  const modulePattern =
    /\bfrom\s*['"]([^'"]+)['"]|\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s*['"]([^'"]+)['"]/g
  let moduleMatch
  while ((moduleMatch = modulePattern.exec(entry.content)) !== null) {
    const specifier = moduleMatch.slice(1).find(Boolean)
    const client = CLIENT_PACKAGES_BY_SPECIFICITY.find((item) =>
      specifier === item.package || specifier.startsWith(`${item.package}/`))
    if (!client) continue
    addObservation(observations, {
      kind: 'client',
      subtype: 'source-import',
      signatureId: client.signature,
      engines: [client.engine],
      deployments: client.deployment ? [client.deployment] : [],
      versions: [],
      evidence: evidence(
        entry.path,
        lineNumberAt(entry.content, moduleMatch.index),
        client.signature,
      ),
    })
  }
  if (
    !/(?:psycopg|asyncpg|pymysql|mysql\.connector|pymongo|motor|snowflake|boto3|google\.cloud|elasticsearch|opensearchpy|neo4j|cassandra|pinecone|qdrant|weaviate|sqlalchemy|django\.db|AWS\.DynamoDB|DynamoDB(?:Document)?Client|getFirestore|admin\.firestore|Npgsql|SqlConnection|MongoClient|DriverManager|getConnection|JdbcTemplate|DbContext|EntityFrameworkCore|github\.com\/(?:jackc\/pgx|lib\/pq|go-sql-driver\/mysql|redis\/go-redis|mongodb\/mongo-go-driver)|go\.mongodb\.org\/mongo-driver|database\/sql|org\.postgresql|com\.mysql\.cj\.jdbc|com\.microsoft\.sqlserver\.jdbc|require\s+['"](?:pg|redis)['"]|\bredis\b)/.test(
      entry.content,
    )
  ) return
  for (const client of LANGUAGE_CLIENTS) {
    if (client.pathPattern && !client.pathPattern.test(entry.path)) continue
    const pattern = new RegExp(client.pattern.source, client.pattern.flags)
    const match = pattern.exec(entry.content)
    if (!match) continue
    addObservation(observations, {
      kind: 'client',
      subtype: 'source-import-or-constructor',
      signatureId: client.signature,
      engines: client.engine ? [client.engine] : [],
      deployments: [],
      versions: [],
      evidence: evidence(
        entry.path,
        lineNumberAt(entry.content, match.index),
        client.signature,
      ),
    })
  }
}

function scanRuntimeResources(entry, observations) {
  const hasSqliteClient = [...observations.values()].some((observation) =>
    observation.kind === 'client'
    && observation.engines.includes('sqlite'))
  if (!hasSqliteClient) return

  const constructorNames = new Set(['Database'])
  for (const pattern of [
    /\bimport\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s*['"](?:better-sqlite3|sqlite3)['"]/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"](?:better-sqlite3|sqlite3)['"]\s*\)/g,
  ]) {
    let aliasMatch
    while ((aliasMatch = pattern.exec(entry.content)) !== null) {
      constructorNames.add(aliasMatch[1])
    }
  }

  let runtimeMatch = null
  for (const constructorName of [...constructorNames].sort(compareText)) {
    const pattern = new RegExp(
      `\\bnew\\s+${constructorName.replaceAll('$', '\\$')}\\s*\\(`,
    )
    const match = pattern.exec(entry.content)
    if (
      match
      && (runtimeMatch === null || match.index < runtimeMatch.index)
    ) runtimeMatch = match
  }
  if (!runtimeMatch) return

  addObservation(observations, {
    kind: 'store',
    subtype: 'declared-resource',
    signatureId: 'resource.runtime.sqlite-open',
    symbol: 'embedded-sqlite-runtime',
    engines: ['sqlite'],
    deployments: ['sqlite-embedded'],
    versions: [],
    evidence: evidence(
      entry.path,
      lineNumberAt(entry.content, runtimeMatch.index),
      'resource.runtime.sqlite-open',
    ),
  })
  addObservation(observations, {
    kind: 'binding',
    subtype: 'file-binding',
    signatureId: 'binding.runtime.sqlite-open',
    token: 'SQLITE_FILE',
    engines: ['sqlite'],
    deployments: ['sqlite-embedded'],
    versions: [],
    evidence: evidence(
      entry.path,
      lineNumberAt(entry.content, runtimeMatch.index),
      'binding.runtime.sqlite-open',
    ),
  })
}

// Every quantifier here must stay newline-free: an untrusted target file may be
// one 16 MiB whitespace run, and a newline-crossing quantifier scans it once per
// candidate boundary.
const RESOURCE_BLOCK_BOUNDARY =
  /\n(?:[ \t]*resource[ \t]+(?:['"]|[A-Za-z_])|[ \t]{0,16}[A-Za-z][A-Za-z0-9]*[ \t]*:[ \t]*(?:\r?\n[ \t]*)*\r?\n[ \t]+Type[ \t]*:|[ \t]*['"]type['"][ \t]*:)/g

function resourceBlock(content, start) {
  RESOURCE_BLOCK_BOUNDARY.lastIndex = start + 1
  const boundary = RESOURCE_BLOCK_BOUNDARY.exec(content)
  return content.slice(start, boundary ? boundary.index : content.length)
}

function normalizeContainerEngine(value) {
  const normalized = value.toLowerCase()
  if (
    normalized === 'postgres'
    || normalized === 'aurora-postgresql'
    || normalized === 'postgresql'
  ) return 'postgresql'
  if (normalized === 'aurora-mysql') return 'mysql'
  if (normalized === 'mongo') return 'mongodb'
  if (normalized.startsWith('oracle-')) return 'oracle'
  if (normalized.startsWith('sqlserver')) return 'sqlserver'
  return normalized
}

function normalizeServerVersion(value, engine) {
  if (!value) return null
  const prefixes = {
    postgresql: /^POSTGRES_/i,
    mysql: /^MYSQL_/i,
    sqlserver: /^SQLSERVER_/i,
  }
  const withoutEngine = prefixes[engine]?.test(value)
    ? value.replace(prefixes[engine], '')
    : value
  return withoutEngine.replaceAll('_', '.')
}

function scanResources(entry, observations, tokens, gaps) {
  if (
    !/\bresource\b|\bimage\s*[:=]|\[\[d1_databases\]\]|AWS::(?:RDS|DynamoDB|ElastiCache|OpenSearchService)|Microsoft\.(?:DBfor(?:PostgreSQL|MySQL)|Cache\/redis(?:Enterprise)?)|apiVersion\s*:\s*(?:postgresql\.cnpg\.io|psmdb\.percona\.com|redis\.redis\.opstreelabs\.in)/i.test(
      entry.content,
    )
  ) return
  for (const definition of RESOURCE_SIGNATURES) {
    const pattern = new RegExp(definition.pattern.source, definition.pattern.flags)
    let match
    let occurrence = 0
    while ((match = pattern.exec(entry.content)) !== null) {
      occurrence += 1
      if (occurrence > HARD_LIMITS.max_resource_matches) {
        gaps.push({
          code: 'resource-signature-match-cap',
          subject: definition.signature,
          detail: `${stableId('source', entry.path)} reached the ${
            HARD_LIMITS.max_resource_matches
          } per-signature match cap; later matches were not observed`,
        })
        break
      }
      const rawEngine = definition.engineGroup
        ? match[definition.engineGroup]?.toLowerCase()
        : definition.engine
      const symbol = definition.engineGroup
        ? `database-resource-${occurrence}`
        : match[1] ?? `database-resource-${occurrence}`
      const block = definition.enginePattern || definition.versionPattern
        ? resourceBlock(entry.content, match.index)
        : ''
      const declaredEngineMatch = definition.enginePattern?.exec(block) ?? null
      const engine = rawEngine
        ? normalizeContainerEngine(rawEngine)
        : declaredEngineMatch
          ? normalizeContainerEngine(declaredEngineMatch[1])
          : null
      let version = definition.versionGroup ? match[definition.versionGroup] : null
      let versionIndex = match.index
      if (!version && definition.versionPattern) {
        const versionMatch = definition.versionPattern.exec(block)
        version = versionMatch?.[1] ?? null
        if (versionMatch) versionIndex = match.index + versionMatch.index
      }
      version = normalizeServerVersion(version, engine)
      const resourceToken = canonicalToken(symbol)
      if (isStrongDatabaseToken(resourceToken)) tokens.add(resourceToken)
      addObservation(observations, {
        kind: 'store',
        subtype: 'declared-resource',
        signatureId: definition.signature,
        symbol,
        token: isStrongDatabaseToken(resourceToken) ? resourceToken : null,
        engines: engine ? [engine] : [],
        deployments: definition.deployment ? [definition.deployment] : [],
        versions: version ? [version] : [],
        evidence: evidence(
          entry.path,
          lineNumberAt(entry.content, match.index),
          definition.signature,
        ),
      })
      if (version) {
        addObservation(observations, {
          kind: 'artifact',
          subtype: 'declared-server-version',
          signatureId: `${definition.signature}.server-version-property`,
          symbol,
          engines: engine ? [engine] : [],
          deployments: definition.deployment ? [definition.deployment] : [],
          versions: [version],
          seedEligible: false,
          evidence: evidence(
            entry.path,
            lineNumberAt(entry.content, versionIndex),
            `${definition.signature}.server-version-property`,
          ),
        })
      }
    }
  }
}

function scanBindings(entry, observations, tokens) {
  if (
    !/(?:DATABASE|POSTGRES|POSTGRESQL|MYSQL|MARIADB|MONGO|REDIS|SQLSERVER|ORACLE|DYNAMODB|FIRESTORE|ELASTICSEARCH|OPENSEARCH|NEO4J|CASSANDRA|BIGQUERY|SNOWFLAKE|PINECONE|QDRANT|WEAVIATE|SUPABASE|NEON|TURSO|PLANETSCALE|UPSTASH|JDBC|CONNECTION|DB_(?:URL|URI|DSN)|\bPG(?:URL|URI|DSN|HOST|PORT|DATABASE|USER|PASSWORD)|databaseUrl|databaseUri|databaseDsn|dbUrl|dbUri|connectionString|postgresUrl|postgresUri|mongoUrl|mongoUri|redisUrl|jdbcUrl)/.test(
      entry.content,
    )
  ) return
  for (const basePattern of [BINDING_TOKEN_PATTERN, CAMEL_BINDING_PATTERN]) {
    const pattern = new RegExp(basePattern.source, basePattern.flags)
    let match
    while ((match = pattern.exec(entry.content)) !== null) {
      const token = canonicalToken(match[1] ?? match[0])
      if (!isStrongDatabaseToken(token)) continue
      tokens.add(token)
      const role = token === 'CONNECTION_STRING'
        ? 'ambiguous-connection'
        : bindingRole(token)
      addObservation(observations, {
        kind: 'binding',
        subtype: `${role}-binding`,
        signatureId: 'binding.strong-config-token',
        token,
        engines: engineForToken(token) ? [engineForToken(token)] : [],
        deployments: [],
        versions: [],
        evidence: evidence(
          entry.path,
          lineNumberAt(entry.content, match.index),
          'binding.strong-config-token',
        ),
      })
    }
  }

  const uriPattern =
    /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|sqlserver|oracle|cassandra|neo4j|snowflake):\/\//gi
  let uriMatch
  while ((uriMatch = uriPattern.exec(entry.content)) !== null) {
    const scheme = uriMatch[1].toLowerCase()
    const engine = URI_ENGINES[scheme]
    const token = `${engine.toUpperCase()}_DSN`
    tokens.add(token)
    addObservation(observations, {
      kind: 'binding',
      subtype: 'dsn-binding',
      signatureId: 'binding.database-uri-scheme',
      token,
      engines: [engine],
      deployments: [],
      versions: [],
      evidence: evidence(
        entry.path,
        lineNumberAt(entry.content, uriMatch.index),
        'binding.database-uri-scheme',
      ),
    })
  }

  const declaredTokenPattern =
    /\b(?:param|output|var)\s+([A-Za-z_][A-Za-z0-9_]*)\b/g
  let declaredMatch
  while ((declaredMatch = declaredTokenPattern.exec(entry.content)) !== null) {
    const token = canonicalToken(declaredMatch[1])
    if (isStrongDatabaseToken(token)) tokens.add(token)
  }
}

function scanArtifacts(entry, observations) {
  const hasClientEvidence = [...observations.values()].some((observation) =>
    observation.kind === 'client')
  for (const definition of ARTIFACT_SIGNATURES) {
    const guardMatches = !definition.guardPattern
      || definition.guardPattern.test(entry.content)
    let contentMatch = guardMatches
      ? definition.pattern.exec(entry.content)
      : null
    if (
      definition.signature === 'artifact.query-path'
      && !contentMatch
      && hasClientEvidence
    ) {
      contentMatch =
        /\.(?:query|execute|find|findOne|findMany|findUnique|aggregate|search|scan|from|select|insert|update|delete|collection)\s*\(|\b(?:Query|Scan|Get|Put|Update|Delete)Command\s*\(/i.exec(
          entry.content,
        )
    }
    const pathMatch = definition.pathPattern?.exec(entry.path) ?? null
    const match = contentMatch ?? pathMatch
    if (!match) continue
    const kind = definition.subtype === 'principal-or-grant'
      ? 'principal'
      : ['replica', 'cdc', 'backup', 'export', 'cache'].includes(definition.subtype)
        ? 'copy'
        : 'artifact'
    addObservation(observations, {
      kind,
      subtype: definition.subtype,
      signatureId: definition.signature,
      engines: uniqueSorted([
        ...(definition.engines ?? []),
        ...(definition.engine ? [definition.engine] : []),
      ]),
      deployments: definition.deployment ? [definition.deployment] : [],
      versions: [],
      evidence: evidence(
        entry.path,
        contentMatch ? lineNumberAt(entry.content, contentMatch.index) : 1,
        definition.signature,
        'supporting',
      ),
    })
  }
}

function pythonRelativeSpecifier(dots, moduleName) {
  const upward = Math.max(0, dots.length - 1)
  const prefix = upward === 0 ? './' : '../'.repeat(upward)
  return `${prefix}${moduleName.replaceAll('.', '/')}`
}

function scanImports(entry) {
  const imports = []
  const definitions = [
    {
      pattern:
        /\b(?:import\s+(?:[^'"]+?\s+from\s*)?|export\s+[^'"]+?\s+from\s*|require\s*\(\s*|import\s*\(\s*)['"](\.[^'"]+)['"]/g,
      signature: 'link.javascript-relative-import',
      specifier: (match) => match[1],
    },
    {
      pattern: /\bfrom\s+(\.+)([A-Za-z_][A-Za-z0-9_.]*)\s+import\b/g,
      signature: 'link.python-relative-import',
      specifier: (match) => pythonRelativeSpecifier(match[1], match[2]),
    },
    {
      pattern:
        /\bmodule\s+[A-Za-z_][A-Za-z0-9_]*\s+['"](\.[^'"]+\.bicep)['"]/g,
      signature: 'link.bicep-module-path',
      specifier: (match) => match[1],
    },
    {
      pattern: /\bsource\s*=\s*['"](\.[^'"]+)['"]/g,
      signature: 'link.terraform-module-path',
      specifier: (match) => match[1],
    },
    {
      pattern: /\bProjectReference\s+Include=['"](\.[^'"]+\.csproj)['"]/g,
      signature: 'link.dotnet-project-reference',
      specifier: (match) => match[1],
    },
  ]
  for (const definition of definitions) {
    const pattern = new RegExp(definition.pattern.source, definition.pattern.flags)
    let match
    while ((match = pattern.exec(entry.content)) !== null) {
      imports.push({
        specifier: definition.specifier(match),
        line: lineNumberAt(entry.content, match.index),
        signatureId: definition.signature,
      })
    }
  }
  return imports.sort((left, right) =>
    compareText(left.specifier, right.specifier)
      || left.line - right.line
      || compareText(left.signatureId, right.signatureId))
}

function scanEntry(entry) {
  const observations = new Map()
  const tokens = new Set()
  const gaps = []
  scanPackageJson(entry, observations, gaps)
  scanOtherManifests(entry, observations)
  scanSourceClients(entry, observations)
  scanRuntimeResources(entry, observations)
  scanResources(entry, observations, tokens, gaps)
  scanBindings(entry, observations, tokens)
  scanArtifacts(entry, observations)
  return {
    ...entry,
    gaps,
    observations: [...observations.values()]
      .map((observation) => ({
        ...observation,
        evidence: observation.evidence.sort((left, right) =>
          compareText(left.path, right.path)
            || left.line - right.line
            || compareText(left.signature_id, right.signature_id)),
      }))
      .sort((left, right) =>
        compareText(left.kind, right.kind)
          || compareText(left.subtype, right.subtype)
          || compareText(left.token ?? '', right.token ?? '')
          || compareText(left.signatureId, right.signatureId)),
    tokens: [...tokens].sort(),
    imports: scanImports(entry),
  }
}

function resolveRelativeImport(fromPath, specifier, pathSet) {
  if (typeof specifier !== 'string' || !specifier.startsWith('.')) return null
  const base = posix.normalize(posix.join(posix.dirname(fromPath), specifier))
  if (base === '..' || base.startsWith('../')) return null
  const candidates = []
  for (const extension of SOURCE_EXTENSIONS) candidates.push(`${base}${extension}`)
  for (const extension of SOURCE_EXTENSIONS.slice(1)) {
    candidates.push(posix.join(base, `index${extension}`))
  }
  return uniqueSorted(candidates).find((candidate) => pathSet.has(candidate)) ?? null
}

function pathRelationKey(relation) {
  return [
    relation.from,
    relation.to,
    relation.relation,
    relation.token ?? '',
    relation.line ?? 0,
    relation.signatureId,
  ].join('\0')
}

function addPathRelation(relations, seen, relation, budget = null) {
  const key = pathRelationKey(relation)
  if (seen.has(key)) return
  seen.add(key)
  if (budget && relations.length >= budget.limit) {
    budget.omitted += 1
    return
  }
  relations.push(relation)
}

function addNearestProjectSurfaceRelations(
  records,
  relations,
  seen,
  limits,
  gaps,
  relationBudget,
) {
  const projects = new Map()
  for (const record of records) {
    if (record.context.length > 0 || record.observations.length === 0) continue
    const projectRoot = record.componentRoot
    if (!projects.has(projectRoot)) {
      projects.set(projectRoot, {
        clientPaths: [],
        surfacePaths: [],
      })
    }
    const project = projects.get(projectRoot)
    project.surfacePaths.push(record.path)
    if (record.observations.some((observation) =>
      observation.kind === 'client' && observation.seedEligible !== false)) {
      project.clientPaths.push(record.path)
    }
  }

  let emitted = 0
  let omitted = 0
  for (const [projectRoot, project] of [...projects].sort(([left], [right]) =>
    compareText(left, right))) {
    const clientPaths = uniqueSorted(project.clientPaths)
    if (clientPaths.length === 0) continue
    const anchor = clientPaths[0]
    for (const target of uniqueSorted(project.surfacePaths)) {
      if (target === anchor) continue
      if (emitted >= limits.max_nodes) {
        omitted += 1
        continue
      }
      addPathRelation(relations, seen, {
        from: anchor,
        to: target,
        relation: 'NEAREST_PROJECT_DATABASE_SURFACE',
        signatureId: 'link.nearest-project-database-surface',
        projectRoot,
        line: 1,
      }, relationBudget)
      emitted += 1
    }
  }
  if (omitted > 0) {
    gaps.push({
      code: 'project-surface-link-cap',
      subject: 'nearest-project-membership',
      detail: `${omitted} project-surface links were omitted at the ${limits.max_nodes} link cap`,
    })
  }
}

function buildPathRelations(records, roots, limits, gaps) {
  const pathSet = new Set(records.map((record) => record.path))
  const relations = []
  const seen = new Set()
  const relationBudget = { limit: limits.max_edges, omitted: 0 }
  for (const record of records) {
    for (const item of record.imports) {
      const target = resolveRelativeImport(record.path, item.specifier, pathSet)
      if (!target) continue
      addPathRelation(relations, seen, {
        from: record.path,
        to: target,
        relation: 'EXACT_RELATIVE_IMPORT',
        signatureId: item.signatureId,
        line: item.line,
      }, relationBudget)
    }
  }

  const tokenPaths = new Map()
  for (const record of records.filter((item) => item.context.length === 0)) {
    const group = projectGroupFor(record.path, roots)
    for (const token of record.tokens) {
      const key = `${group}\0${token}`
      if (!tokenPaths.has(key)) tokenPaths.set(key, [])
      tokenPaths.get(key).push(record.path)
    }
  }
  for (const [key, rawPaths] of [...tokenPaths].sort(([left], [right]) =>
    compareText(left, right))) {
    const paths = uniqueSorted(rawPaths)
    if (paths.length < 2) continue
    const [group, token] = key.split('\0')
    if (paths.length > limits.max_token_fanout) {
      gaps.push({
        code: 'token-fanout-cap',
        subject: token,
        detail: `${paths.length} paths in ${stableId('component', group)} share the token; cap is ${limits.max_token_fanout}`,
      })
      continue
    }
    const anchor = paths[0]
    for (const target of paths.slice(1)) {
      addPathRelation(relations, seen, {
        from: anchor,
        to: target,
        relation: 'EXACT_CONFIG_TOKEN',
        signatureId: 'link.exact-strong-config-token',
        token,
        line: 1,
      }, relationBudget)
    }
  }
  addNearestProjectSurfaceRelations(
    records,
    relations,
    seen,
    limits,
    gaps,
    relationBudget,
  )
  if (relationBudget.omitted > 0) {
    gaps.push({
      code: 'path-relation-cap',
      subject: 'discovery-fixed-point',
      detail: `${relationBudget.omitted} path relations were omitted at the ${limits.max_edges} relation cap`,
    })
  }
  return relations.sort((left, right) =>
    compareText(pathRelationKey(left), pathRelationKey(right)))
}

function reasonKey(reason) {
  return canonicalJson(reason)
}

function addScopeReason(scopeReasons, repositoryPath, reason) {
  if (!scopeReasons.has(repositoryPath)) scopeReasons.set(repositoryPath, [])
  const reasons = scopeReasons.get(repositoryPath)
  if (!reasons.some((item) => reasonKey(item) === reasonKey(reason))) reasons.push(reason)
}

function traversePaths(records, relations, limits, gaps) {
  const recordMap = new Map(records.map((record) => [record.path, record]))
  const adjacency = new Map(records.map((record) => [record.path, []]))
  for (const relation of relations) {
    adjacency.get(relation.from)?.push({ relation, neighbor: relation.to })
    adjacency.get(relation.to)?.push({ relation, neighbor: relation.from })
  }
  for (const links of adjacency.values()) {
    links.sort((left, right) =>
      compareText(left.neighbor, right.neighbor)
        || compareText(pathRelationKey(left.relation), pathRelationKey(right.relation)))
  }

  const seedPaths = records
    .filter((record) =>
      record.context.length === 0
      && record.observations.some((observation) => observation.seedEligible !== false))
    .map((record) => record.path)
    .sort()

  const visited = new Set()
  const scopeReasons = new Map()
  let frontier = []
  for (const repositoryPath of seedPaths) {
    if (visited.size >= limits.max_nodes) {
      gaps.push({
        code: 'traversal-node-cap',
        subject: 'seed-paths',
        detail: `discovery reached the ${limits.max_nodes} path traversal cap`,
      })
      break
    }
    visited.add(repositoryPath)
    frontier.push(repositoryPath)
    const signatures = uniqueSorted(
      recordMap.get(repositoryPath).observations
        .filter((observation) => observation.seedEligible !== false)
        .map((observation) => observation.signatureId),
    )
    addScopeReason(scopeReasons, repositoryPath, {
      code: 'database-evidence-seed',
      signatures,
    })
  }

  let rounds = 0
  let traversalCapped = false
  while (frontier.length > 0 && rounds < limits.max_rounds && !traversalCapped) {
    rounds += 1
    const next = []
    for (const current of frontier.sort()) {
      for (const { relation, neighbor } of adjacency.get(current) ?? []) {
        if (visited.has(neighbor)) continue
        if (visited.size >= limits.max_nodes) {
          traversalCapped = true
          break
        }
        visited.add(neighbor)
        next.push(neighbor)
        addScopeReason(scopeReasons, neighbor, {
          code: relation.relation === 'EXACT_RELATIVE_IMPORT'
            ? 'exact-relative-import'
            : relation.relation === 'EXACT_CONFIG_TOKEN'
              ? 'exact-strong-config-token'
              : 'nearest-project-database-surface',
          source_path: current,
          signature_id: relation.signatureId,
          ...(relation.token ? { token: relation.token } : {}),
        })
      }
      if (traversalCapped) break
    }
    frontier = uniqueSorted(next)
  }
  if (traversalCapped && !gaps.some((gap) => gap.code === 'traversal-node-cap')) {
    gaps.push({
      code: 'traversal-node-cap',
      subject: 'reachable-paths',
      detail: `discovery reached the ${limits.max_nodes} path traversal cap`,
    })
  }
  if (frontier.length > 0) {
    gaps.push({
      code: 'fixed-point-round-cap',
      subject: 'reachable-paths',
      detail: `discovery stopped after ${limits.max_rounds} fixed-point rounds`,
    })
  }
  return { visited, scopeReasons, rounds }
}

function observationNodeId(record, observation) {
  return stableId(
    observation.kind,
    record.path,
    observation.subtype,
    observation.signatureId,
    observation.token ?? '',
    observation.symbol ?? '',
    ...(observation.engines ?? []),
  )
}

function observationLabel(observation) {
  if (observation.kind === 'binding') return `${observation.token} database binding`
  if (observation.kind === 'store') {
    return `${observation.engines[0] ?? 'database'} declared resource`
  }
  if (observation.kind === 'client') {
    return `${observation.engines[0] ?? 'database'} client evidence`
  }
  return observation.subtype.replaceAll('-', ' ')
}

function graphEvidenceForObservation(observation) {
  return observation.evidence.map((item) => ({ ...item }))
}

function sortedGraphItems(items, idKey) {
  return [...items].sort((left, right) => compareText(left[idKey], right[idKey]))
}

function makeGap(rawGap) {
  return {
    gap_id: stableId('gap', rawGap.code, rawGap.subject, rawGap.detail),
    code: rawGap.code,
    subject: rawGap.subject,
    detail: rawGap.detail,
  }
}

function makeUnresolved(type, repositoryPath, nodeIds, reasons) {
  const sortedNodeIds = uniqueSorted(nodeIds)
  const sortedReasons = uniqueSorted(reasons)
  return {
    observation_id: stableId(
      'unresolved',
      type,
      repositoryPath ?? '',
      ...sortedNodeIds,
      ...sortedReasons,
    ),
    type,
    ...(repositoryPath ? { path: repositoryPath } : {}),
    node_ids: sortedNodeIds,
    reasons: sortedReasons,
  }
}

function compatibleEngine(observation, engine) {
  return observation.engines.length === 0
    || engine === null
    || observation.engines.includes(engine)
}

function candidateConfidence(resource, clients, bindings) {
  if (resource) return 'high'
  if (clients.length > 0 && bindings.length > 0) return 'medium'
  return 'low'
}

function candidateFor({
  anchor,
  engine,
  resource,
  clients,
  bindings,
  related,
  clusterPaths,
  recordMap,
}) {
  const all = [resource, ...clients, ...bindings, ...related].filter(Boolean)
  const nodeIds = uniqueSorted(all.map((observation) => observation.nodeId))
  const engineCandidates = uniqueSorted([
    ...(engine ? [engine] : []),
    ...all.flatMap((observation) => observation.engines),
  ])
  const versionCandidates = uniqueSorted(
    resource?.versions ?? [],
  )
  const deploymentCandidates = uniqueSorted(
    all.flatMap((observation) => observation.deployments),
  )
  const evidencePaths = uniqueSorted(
    all.flatMap((observation) => observation.evidence.map((item) => item.path)),
  )
  const componentNodeIds = uniqueSorted(
    all.map((observation) =>
      stableId('component', recordMap.get(observation.path).componentRoot)),
  )
  const openReasons = []
  if (engineCandidates.length === 0) openReasons.push('engine-unresolved')
  if (engineCandidates.length > 1) openReasons.push('engine-evidence-conflict')
  if (versionCandidates.length === 0) openReasons.push('server-version-unresolved')
  if (clients.length === 0) openReasons.push('client-usage-unresolved')
  if (bindings.length === 0) openReasons.push('connection-binding-unresolved')

  return {
    store_id: stableId(
      'store',
      resource?.nodeId ?? anchor.nodeId,
      engine ?? 'unknown-engine',
    ),
    anchor_node_id: resource?.nodeId ?? anchor.nodeId,
    component_node_ids: componentNodeIds,
    node_ids: nodeIds,
    engine_candidates: engineCandidates,
    engine_version_candidates: versionCandidates,
    deployment_candidates: deploymentCandidates,
    confidence: candidateConfidence(resource, clients, bindings),
    context_only: false,
    evidence_paths: evidencePaths,
    scope_paths: uniqueSorted(clusterPaths),
    open_reasons: uniqueSorted(openReasons),
  }
}

function buildCandidates(activeObservations, visitedRelations, recordMap) {
  const paths = uniqueSorted(activeObservations.map((observation) => observation.path))
  const union = new UnionFind(paths)
  for (const relation of visitedRelations) union.union(relation.from, relation.to)
  const groups = new Map()
  for (const observation of activeObservations) {
    const root = union.find(observation.path) ?? observation.path
    if (!groups.has(root)) groups.set(root, [])
    groups.get(root).push(observation)
  }

  const candidates = []
  const unresolved = []
  for (const [root, rawGroup] of [...groups].sort(([left], [right]) =>
    compareText(left, right))) {
    const group = rawGroup.sort((left, right) => compareText(left.nodeId, right.nodeId))
    const resources = group.filter((item) => item.kind === 'store')
    const clients = group.filter((item) => item.kind === 'client')
    const bindings = group.filter((item) => item.kind === 'binding')
    const related = group.filter((item) =>
      ['artifact', 'principal', 'copy'].includes(item.kind))

    if (resources.length > 0) {
      const resourceMatches = (observation) => resources.filter((resource) => {
        if (observation.subtype === 'declared-server-version') {
          return observation.path === resource.path
            && observation.symbol === resource.symbol
        }
        const engine = resource.engines.length === 1 ? resource.engines[0] : null
        return compatibleEngine(observation, engine)
      })
      for (const resource of resources) {
        const resourceEngine = resource.engines.length === 1 ? resource.engines[0] : null
        const compatibleClients = clients.filter((item) =>
          compatibleEngine(item, resourceEngine)
          && resourceMatches(item).length === 1)
        const compatibleBindings = bindings.filter((item) =>
          compatibleEngine(item, resourceEngine)
          && resourceMatches(item).length === 1)
        const compatibleRelated = related.filter((item) => {
          const matches = resourceMatches(item)
          return matches.length === 1 && matches[0].nodeId === resource.nodeId
        })
        const candidatePaths = uniqueSorted([
          resource.path,
          ...compatibleClients.map((item) => item.path),
          ...compatibleBindings.map((item) => item.path),
          ...compatibleRelated.map((item) => item.path),
        ])
        candidates.push(candidateFor({
          anchor: resource,
          engine: resourceEngine,
          resource,
          clients: compatibleClients,
          bindings: compatibleBindings,
          related: compatibleRelated,
          clusterPaths: candidatePaths,
          recordMap,
        }))
      }
      for (const observation of [...clients, ...bindings, ...related]) {
        const matches = resourceMatches(observation)
        if (matches.length !== 1) {
          const isArtifact = ['artifact', 'principal', 'copy'].includes(observation.kind)
          unresolved.push(makeUnresolved(
            matches.length === 0
              ? isArtifact ? 'artifact-engine-mismatch' : 'resource-engine-mismatch'
              : isArtifact ? 'ambiguous-artifact-target' : 'ambiguous-resource-target',
            observation.path,
            [observation.nodeId, ...matches.map((item) => item.nodeId)],
            [matches.length === 0
              ? 'no compatible declared resource'
              : 'multiple compatible declared resources'],
          ))
        }
      }
      continue
    }

    const knownEngines = uniqueSorted(
      [...clients, ...bindings, ...related].flatMap((item) => item.engines),
    )
    if (bindings.length > 0) {
      const decisiveBindings = bindings.filter((item) =>
        item.subtype !== 'ambiguous-connection-binding')
      if (decisiveBindings.length === 0 && clients.length === 0) {
        unresolved.push(makeUnresolved(
          'ambiguous-connection-config',
          bindings[0].path,
          bindings.map((item) => item.nodeId),
          ['generic connection string is not connected to database client or resource evidence'],
        ))
        continue
      }
      const candidateEngines = knownEngines.length > 0 ? knownEngines : [null]
      for (const engine of candidateEngines) {
        const unambiguousUnknown = candidateEngines.length === 1
        const matchesEngine = (item) =>
          item.engines.includes(engine)
          || (item.engines.length === 0 && unambiguousUnknown)
        const matchingClients = clients.filter(matchesEngine)
        const matchingBindings = bindings.filter(matchesEngine)
        const matchingRelated = related.filter(matchesEngine)
        if (matchingBindings.length === 0) continue
        const anchor = [...matchingBindings].sort((left, right) =>
          compareText(left.token ?? '', right.token ?? '')
            || compareText(left.path, right.path)
            || compareText(left.nodeId, right.nodeId))[0]
        const candidatePaths = uniqueSorted(
          [...matchingClients, ...matchingBindings, ...matchingRelated]
            .map((item) => item.path),
        )
        candidates.push(candidateFor({
          anchor,
          engine,
          resource: null,
          clients: matchingClients,
          bindings: matchingBindings,
          related: matchingRelated,
          clusterPaths: candidatePaths,
          recordMap,
        }))
      }
      if (knownEngines.length > 1) {
        for (const binding of bindings.filter((item) => item.engines.length === 0)) {
          unresolved.push(makeUnresolved(
            'ambiguous-binding-target',
            binding.path,
            [binding.nodeId],
            ['generic binding is connected to multiple client engines'],
          ))
        }
      }
    } else if (clients.length > 0) {
      for (const client of clients) {
        unresolved.push(makeUnresolved(
          'client-without-connection-binding',
          client.path,
          [client.nodeId],
          ['client evidence does not identify a connection binding or declared resource'],
        ))
      }
    }

    if (clients.length === 0 && bindings.length === 0 && related.length > 0) {
      unresolved.push(makeUnresolved(
        'database-artifact-without-store',
        root,
        related.map((item) => item.nodeId),
        ['database artifact is not connected to a client, binding, or declared resource'],
      ))
    }
  }
  return {
    candidates: sortedGraphItems(candidates, 'store_id'),
    unresolved: sortedGraphItems(unresolved, 'observation_id'),
  }
}

function addCandidateEdges(candidates, observationByNodeId, addEdge) {
  for (const candidate of candidates) {
    const anchor = observationByNodeId.get(candidate.anchor_node_id)
    if (!anchor) continue
    const observations = candidate.node_ids
      .map((nodeId) => observationByNodeId.get(nodeId))
      .filter(Boolean)
      .sort((left, right) => compareText(left.nodeId, right.nodeId))
    const clients = observations.filter((item) => item.kind === 'client')
    const bindings = observations.filter((item) => item.kind === 'binding')
    const related = observations.filter((item) =>
      ['artifact', 'principal', 'copy'].includes(item.kind))
    for (const client of clients) {
      for (const binding of bindings) {
        addEdge(client.nodeId, binding.nodeId, 'USES_BINDING', client.evidence[0])
      }
    }
    if (anchor.kind === 'store') {
      for (const binding of bindings) {
        addEdge(binding.nodeId, anchor.nodeId, 'TARGETS_STORE', binding.evidence[0])
      }
    }
    for (const item of related) {
      if (item.nodeId === anchor.nodeId) continue
      addEdge(item.nodeId, anchor.nodeId, 'APPLIES_TO_STORE', item.evidence[0])
    }
  }
}

function pathScope(entries, recordMap, visited, scopeReasons) {
  return entries.map((entry) => {
    const record = recordMap.get(entry.path)
    const observed = (record?.observations.length ?? 0) > 0
    let state
    const reasons = [...(scopeReasons.get(entry.path) ?? [])]
    if (visited.has(entry.path)) {
      state = 'in-scope'
    } else if (entry.kind !== 'text' || entry.content === null) {
      state = 'out-of-scope'
      reasons.push({ code: 'non-text-entry' })
    } else if (entry.context.length > 0 && observed) {
      state = 'context-only'
      reasons.push({ code: 'context-evidence-not-connected' })
    } else if (observed) {
      state = 'out-of-scope'
      const onlyNonSeeding = record.observations.every((observation) =>
        observation.seedEligible === false)
      reasons.push({
        code: onlyNonSeeding
          ? 'non-seeding-context-evidence'
          : 'traversal-cap-before-path',
      })
    } else {
      state = 'out-of-scope'
      reasons.push({ code: 'no-database-evidence' })
    }
    return {
      path: entry.path,
      state,
      context_classifications: entry.context,
      reasons: reasons.sort((left, right) => compareText(reasonKey(left), reasonKey(right))),
    }
  })
}

function graphWithoutDigest(graph) {
  const clone = deepClone(graph)
  delete clone.digest
  return clone
}

function computeGraphDigest(graph) {
  return `sha256:${sha256(canonicalJson(graphWithoutDigest(graph)))}`
}

function noCredentialBearingUri(value) {
  return !/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/.test(value)
}

function noLiteralUri(value) {
  return !/[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)
}

export class DatabaseDiscoveryValidationError extends Error {
  constructor(errors) {
    super(`Invalid database discovery graph:\n- ${errors.join('\n- ')}`)
    this.name = 'DatabaseDiscoveryValidationError'
    this.errors = Object.freeze([...errors])
  }
}

export function validateDatabaseDiscovery(graph) {
  const errors = []
  if (!isPlainObject(graph)) {
    return { valid: false, errors: ['graph must be an object'] }
  }
  let schemaValid = false
  try {
    schemaValid = validateDatabaseDiscoverySchema(graph)
  } catch (error) {
    errors.push(
      `schema validation failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  if (!schemaValid) {
    for (const error of validateDatabaseDiscoverySchema.errors ?? []) {
      const location = error.instancePath || '/'
      errors.push(`schema${location} ${error.message ?? 'is invalid'}`)
    }
  }
  if (graph.schema_version !== DATABASE_DISCOVERY_SCHEMA_VERSION) {
    errors.push(`schema_version must be ${DATABASE_DISCOVERY_SCHEMA_VERSION}`)
  }
  if (graph.kind !== DATABASE_DISCOVERY_KIND) {
    errors.push(`kind must be ${DATABASE_DISCOVERY_KIND}`)
  }
  for (const key of [
    'nodes',
    'edges',
    'store_candidates',
    'unresolved',
    'gaps',
    'path_scope',
  ]) {
    if (!Array.isArray(graph[key])) errors.push(`${key} must be an array`)
  }
  if (!isPlainObject(graph.limits)) errors.push('limits must be an object')
  if (!isPlainObject(graph.stats)) errors.push('stats must be an object')

  const nodes = Array.isArray(graph.nodes) ? graph.nodes : []
  const edges = Array.isArray(graph.edges) ? graph.edges : []
  const nodeIds = new Set()
  const nodeById = new Map()
  for (const [index, node] of nodes.entries()) {
    if (!isPlainObject(node) || typeof node.node_id !== 'string') {
      errors.push(`nodes[${index}] must contain node_id`)
      continue
    }
    if (nodeIds.has(node.node_id)) errors.push(`duplicate node_id ${node.node_id}`)
    nodeIds.add(node.node_id)
    nodeById.set(node.node_id, node)
    if (!Array.isArray(node.evidence)) errors.push(`node ${node.node_id} evidence must be an array`)
    if (
      node.kind !== 'store'
      && node.subtype !== 'declared-server-version'
      && Array.isArray(node.engine_version_candidates)
      && node.engine_version_candidates.length > 0
    ) {
      errors.push(`node ${node.node_id} has a non-server version candidate`)
    }
    if (!noCredentialBearingUri(canonicalJson(node))) {
      errors.push(`node ${node.node_id} contains a credential-bearing URI`)
    }
  }
  const edgeIds = new Set()
  for (const [index, edge] of edges.entries()) {
    if (!isPlainObject(edge) || typeof edge.edge_id !== 'string') {
      errors.push(`edges[${index}] must contain edge_id`)
      continue
    }
    if (edgeIds.has(edge.edge_id)) errors.push(`duplicate edge_id ${edge.edge_id}`)
    edgeIds.add(edge.edge_id)
    if (!nodeIds.has(edge.from_node_id)) {
      errors.push(`edge ${edge.edge_id} has unknown from_node_id`)
    }
    if (!nodeIds.has(edge.to_node_id)) {
      errors.push(`edge ${edge.edge_id} has unknown to_node_id`)
    }
  }
  const storeIds = new Set()
  for (const [index, candidate] of (Array.isArray(graph.store_candidates)
    ? graph.store_candidates
    : []).entries()) {
    if (!isPlainObject(candidate) || typeof candidate.store_id !== 'string') {
      errors.push(`store_candidates[${index}] must contain store_id`)
      continue
    }
    if (storeIds.has(candidate.store_id)) {
      errors.push(`duplicate store_id ${candidate.store_id}`)
    }
    storeIds.add(candidate.store_id)
    if (!nodeIds.has(candidate.anchor_node_id)) {
      errors.push(`store ${candidate.store_id ?? '<unknown>'} has unknown anchor_node_id`)
    }
    if (!Array.isArray(candidate.node_ids)) {
      errors.push(`store ${candidate.store_id} node_ids must be an array`)
    }
    for (const nodeId of Array.isArray(candidate.node_ids) ? candidate.node_ids : []) {
      if (!nodeIds.has(nodeId)) {
        errors.push(`store ${candidate.store_id ?? '<unknown>'} has unknown node_id ${nodeId}`)
      }
    }
    if (!Array.isArray(candidate.component_node_ids)) {
      errors.push(`store ${candidate.store_id} component_node_ids must be an array`)
    }
    for (const nodeId of Array.isArray(candidate.component_node_ids)
      ? candidate.component_node_ids
      : []) {
      if (!nodeIds.has(nodeId) || nodeById.get(nodeId)?.kind !== 'component') {
        errors.push(`store ${candidate.store_id} has unknown component_node_id ${nodeId}`)
      }
    }
    const anchor = nodeById.get(candidate.anchor_node_id)
    if (
      Array.isArray(candidate.engine_version_candidates)
      && candidate.engine_version_candidates.length > 0
    ) {
      if (anchor?.kind !== 'store') {
        errors.push(`store ${candidate.store_id} has a version without a declared-resource anchor`)
      } else {
        const unanchoredVersions = candidate.engine_version_candidates.filter((version) =>
          !anchor.engine_version_candidates?.includes(version))
        if (unanchoredVersions.length > 0) {
          errors.push(
            `store ${candidate.store_id} has server versions absent from its declared-resource anchor: ${
              unanchoredVersions.join(', ')
            }`,
          )
        }
      }
    }
  }
  const unresolvedIds = new Set()
  for (const [index, unresolved] of (Array.isArray(graph.unresolved)
    ? graph.unresolved
    : []).entries()) {
    if (!isPlainObject(unresolved) || typeof unresolved.observation_id !== 'string') {
      errors.push(`unresolved[${index}] must contain observation_id`)
      continue
    }
    if (unresolvedIds.has(unresolved.observation_id)) {
      errors.push(`duplicate observation_id ${unresolved.observation_id}`)
    }
    unresolvedIds.add(unresolved.observation_id)
    if (!Array.isArray(unresolved.node_ids)) {
      errors.push(`unresolved ${unresolved.observation_id} node_ids must be an array`)
    }
    for (const nodeId of Array.isArray(unresolved.node_ids) ? unresolved.node_ids : []) {
      if (!nodeIds.has(nodeId)) {
        errors.push(`unresolved ${unresolved.observation_id} has unknown node_id ${nodeId}`)
      }
    }
  }
  const pathScopePaths = new Set()
  let previousPathScopePath = null
  for (const [index, scope] of (Array.isArray(graph.path_scope)
    ? graph.path_scope
    : []).entries()) {
    if (!isPlainObject(scope) || typeof scope.path !== 'string') {
      errors.push(`path_scope[${index}] must contain path`)
      continue
    }
    if (pathScopePaths.has(scope.path)) errors.push(`duplicate path_scope path ${scope.path}`)
    if (
      previousPathScopePath !== null
      && compareCanonicalStrings(previousPathScopePath, scope.path) >= 0
    ) {
      errors.push('path_scope paths must be in strict canonical order')
    }
    pathScopePaths.add(scope.path)
    previousPathScopePath = scope.path
  }
  const gapIds = new Set()
  for (const [index, gap] of (Array.isArray(graph.gaps) ? graph.gaps : []).entries()) {
    if (!isPlainObject(gap) || typeof gap.gap_id !== 'string') {
      errors.push(`gaps[${index}] must contain gap_id`)
      continue
    }
    if (gapIds.has(gap.gap_id)) errors.push(`duplicate gap_id ${gap.gap_id}`)
    gapIds.add(gap.gap_id)
  }
  if (isPlainObject(graph.limits)) {
    if (nodes.length > graph.limits.max_nodes) errors.push('nodes exceed limits.max_nodes')
    if (edges.length > graph.limits.max_edges) errors.push('edges exceed limits.max_edges')
  }
  if (isPlainObject(graph.stats)) {
    const expectedCounts = {
      node_count: nodes.length,
      edge_count: edges.length,
      store_candidate_count: Array.isArray(graph.store_candidates)
        ? graph.store_candidates.length
        : 0,
      unresolved_count: Array.isArray(graph.unresolved) ? graph.unresolved.length : 0,
      gap_count: Array.isArray(graph.gaps) ? graph.gaps.length : 0,
    }
    for (const [field, expected] of Object.entries(expectedCounts)) {
      if (graph.stats[field] !== expected) {
        errors.push(`stats.${field} must equal ${expected}`)
      }
    }
  }
  if (typeof graph.digest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(graph.digest)) {
    errors.push('digest must be a sha256 digest')
  } else if (graph.digest !== computeGraphDigest(graph)) {
    errors.push('digest does not match the canonical secret-free graph')
  }
  if (!noCredentialBearingUri(canonicalJson(graph))) {
    errors.push('graph contains a credential-bearing URI')
  }
  if (!noLiteralUri(canonicalJson(graph))) {
    errors.push('graph contains a literal URI instead of typed evidence')
  }
  return { valid: errors.length === 0, errors }
}

export function serializeDatabaseDiscovery(graph) {
  const validation = validateDatabaseDiscovery(graph)
  if (!validation.valid) throw new DatabaseDiscoveryValidationError(validation.errors)
  return `${JSON.stringify(canonicalize(graph), null, 2)}\n`
}

export function discoverDatabaseGraph(inventory, options = {}) {
  const limits = normalizeLimits(options)
  const normalized = normalizeInventory(inventory)
  const rawGaps = []
  if (normalized.rejected.length > 0) {
    rawGaps.push({
      code: 'invalid-inventory-entry',
      subject: 'inventory',
      detail: `${normalized.rejected.length} inventory entries were rejected`,
    })
  }
  if (normalized.duplicates.length > 0) {
    rawGaps.push({
      code: 'duplicate-inventory-path',
      subject: 'inventory',
      detail: `${normalized.duplicates.length} duplicate repository paths were ignored`,
    })
  }

  const roots = componentRoots(normalized.entries)
  const textRecords = normalized.entries
    .filter((entry) => entry.kind === 'text' && entry.content !== null)
    .map(scanEntry)
    .map((record) => ({
      ...record,
      componentRoot: componentRootFor(record.path, roots),
    }))
  const recordMap = new Map(textRecords.map((record) => [record.path, record]))
  for (const record of textRecords) rawGaps.push(...record.gaps)
  const pathRelations = buildPathRelations(textRecords, roots, limits, rawGaps)
  const traversal = traversePaths(textRecords, pathRelations, limits, rawGaps)
  const relevantPaths = new Set([
    ...traversal.visited,
    ...textRecords
      .filter((record) => record.context.length > 0 && record.observations.length > 0)
      .map((record) => record.path),
  ])

  const nodes = new Map()
  const edges = new Map()
  let nodeCapHit = false
  let edgeCapHit = false
  const addNode = (node) => {
    if (nodes.has(node.node_id)) return true
    if (nodes.size >= limits.max_nodes) {
      nodeCapHit = true
      return false
    }
    nodes.set(node.node_id, node)
    return true
  }
  const addEdge = (fromNodeId, toNodeId, relation, edgeEvidence) => {
    if (!nodes.has(fromNodeId) || !nodes.has(toNodeId)) return false
    const edgeId = stableId('edge', fromNodeId, toNodeId, relation)
    if (edges.has(edgeId)) return true
    if (edges.size >= limits.max_edges) {
      edgeCapHit = true
      return false
    }
    edges.set(edgeId, {
      edge_id: edgeId,
      from_node_id: fromNodeId,
      to_node_id: toNodeId,
      relation,
      evidence: edgeEvidence ? [{ ...edgeEvidence }] : [],
    })
    return true
  }

  const relevantRecords = textRecords
    .filter((record) => relevantPaths.has(record.path))
    .sort((left, right) => compareText(left.path, right.path))
  for (const record of relevantRecords) {
    const componentId = stableId('component', record.componentRoot)
    addNode({
      node_id: componentId,
      kind: 'component',
      subtype: 'repository-component',
      label: record.componentRoot === '.' ? 'repository root' : `component ${record.componentRoot}`,
      component_root: record.componentRoot,
      context_only: false,
      engine_candidates: [],
      engine_version_candidates: [],
      deployment_candidates: [],
      evidence: [],
    })
    const contextOnly = record.context.length > 0 && !traversal.visited.has(record.path)
    const sourceId = stableId('source', record.path)
    addNode({
      node_id: sourceId,
      kind: 'source',
      subtype: 'inventory-text-file',
      label: record.path,
      component_root: record.componentRoot,
      context_only: contextOnly,
      engine_candidates: [],
      engine_version_candidates: [],
      deployment_candidates: [],
      evidence: [],
    })
    addEdge(componentId, sourceId, 'CONTAINS', null)
  }

  const observationByNodeId = new Map()
  for (const record of relevantRecords) {
    const sourceId = stableId('source', record.path)
    const contextOnly = record.context.length > 0 && !traversal.visited.has(record.path)
    for (const observation of record.observations) {
      const nodeId = observationNodeId(record, observation)
      const added = addNode({
        node_id: nodeId,
        kind: observation.kind,
        subtype: observation.subtype,
        label: observationLabel(observation),
        component_root: record.componentRoot,
        context_only: contextOnly,
        engine_candidates: observation.engines,
        engine_version_candidates: observation.versions,
        deployment_candidates: observation.deployments,
        evidence: graphEvidenceForObservation(observation),
      })
      if (!added) continue
      const internal = {
        ...observation,
        nodeId,
        path: record.path,
        contextOnly,
      }
      observationByNodeId.set(nodeId, internal)
      addEdge(sourceId, nodeId, 'DECLARES', observation.evidence[0])
    }
  }

  const visitedRelations = pathRelations.filter((relation) =>
    traversal.visited.has(relation.from) && traversal.visited.has(relation.to))
  for (const relation of visitedRelations) {
    if (relation.relation === 'NEAREST_PROJECT_DATABASE_SURFACE') continue
    addEdge(
      stableId('source', relation.from),
      stableId('source', relation.to),
      relation.relation,
      evidence(relation.from, relation.line, relation.signatureId),
    )
  }

  const activeObservations = [...observationByNodeId.values()]
    .filter((observation) =>
      traversal.visited.has(observation.path) && !observation.contextOnly)
  const candidateResult = buildCandidates(activeObservations, visitedRelations, recordMap)

  const contextUnresolved = []
  for (const record of relevantRecords.filter((item) =>
    item.context.length > 0 && !traversal.visited.has(item.path))) {
    const nodeIds = record.observations
      .map((observation) => observationNodeId(record, observation))
      .filter((nodeId) => nodes.has(nodeId))
    if (nodeIds.length === 0) continue
    contextUnresolved.push(makeUnresolved(
      'context-only-evidence',
      record.path,
      nodeIds,
      [`unconnected ${record.context.join(', ')} evidence did not seed a store`],
    ))
  }

  addCandidateEdges(candidateResult.candidates, observationByNodeId, addEdge)
  if (nodeCapHit) {
    rawGaps.push({
      code: 'graph-node-cap',
      subject: 'discovery-graph',
      detail: `graph output reached the ${limits.max_nodes} node cap`,
    })
  }
  if (edgeCapHit) {
    rawGaps.push({
      code: 'graph-edge-cap',
      subject: 'discovery-graph',
      detail: `graph output reached the ${limits.max_edges} edge cap`,
    })
  }

  const graph = {
    schema_version: DATABASE_DISCOVERY_SCHEMA_VERSION,
    kind: DATABASE_DISCOVERY_KIND,
    digest: '',
    limits: { ...limits },
    stats: {
      inventory_entries: normalized.entries.length,
      text_entries: textRecords.length,
      evidence_paths: textRecords.filter((record) => record.observations.length > 0).length,
      in_scope_paths: traversal.visited.size,
      fixed_point_rounds: traversal.rounds,
      node_count: nodes.size,
      edge_count: edges.size,
      store_candidate_count: candidateResult.candidates.length,
      unresolved_count: candidateResult.unresolved.length + contextUnresolved.length,
      gap_count: rawGaps.length,
    },
    nodes: sortedGraphItems(nodes.values(), 'node_id'),
    edges: sortedGraphItems(edges.values(), 'edge_id'),
    store_candidates: candidateResult.candidates,
    unresolved: sortedGraphItems(
      [...candidateResult.unresolved, ...contextUnresolved],
      'observation_id',
    ),
    gaps: sortedGraphItems(
      rawGaps.map(makeGap),
      'gap_id',
    ),
    path_scope: pathScope(
      normalized.entries,
      recordMap,
      traversal.visited,
      traversal.scopeReasons,
    ),
  }
  graph.stats.gap_count = graph.gaps.length
  graph.digest = computeGraphDigest(graph)
  const validation = validateDatabaseDiscovery(graph)
  if (!validation.valid) throw new DatabaseDiscoveryValidationError(validation.errors)
  return graph
}
