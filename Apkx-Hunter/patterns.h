#ifndef PATTERNS_H
#define PATTERNS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

const char *patterns[] = {
    /* authentication & identity */
    
    "/login",
    "/logout",
    "/token",
    "/oauth",
    "/sso",
    "/saml",
    "/signin",
    "/signup",
    "/register",
    "/refresh",
    "/session",
    "/password",
    "/reset",
    "/verify",
    "/2fa",
    "/mfa",
    "/otp",
    "/authenticate",
    "/authorize",
    "/callback",
    "/credentials",
    "/jwt",
    "/idp",

    /* admin / internal / debug */
    "/api/",
    "/rest/",
    "/admin",
    "/debug",
    "/staging",
    "/dev",
    "/test",
    "/private",
    "/secret",
    "/backdoor",
    "/manage",
    "/console",
    "/dashboard",
    "/configuration",
    "/env",
    "/actuator",
    "/swagger",
    "/sandbox",
    "/shell",

    /* monitoring / observability */
    "/health",
    "/metrics",
    "/trace",
    "/heapdump",
    "/jmx",
    "/logs",
    "/dump",

    /* graphql */
    "/graphql",
    "/gql",
    "/__schema",
    "/playground",
    "/graphiql",
    "/introspection",

    /* payments & billing */
    
    "/checkout",
    "/order",
    "/billing",
    "/invoice",
    "/stripe",
    "/paypal",
    "/purchase",
    "/transaction",
    "/refund",
    "/charge",
    "/tax",

    /* user / account */
    "/account",
    "/customer",
    "/preferences",
    "/avatar",

    /* files / storage */
    "/upload",
    "/download",
    "/file",
    "/attachment",
    "/asset",
    "/storage",
    "/backup",
    "/export",
    "/import",
    "/bucket",

    /* mobile / app-specific */
    "/firebase",
    "/push",
    "/webhook",
    "/apikey",
    "/api-key",
    "/client-secret",
    "/remoteconfig",
    "/appconfig",
    "/crashlytics",
    "/analytics",
    

    /* misc sensitive paths */
    "/.git",
    "/.env",
    "/.well-known",

};


typedef struct
{
    const char *name;
    const char *pattern;
} Full_manifest_scan;

Full_manifest_scan manifest_scan[] = {

    
    {"Exported_ACTIVITY", "android:exported=\"true\""},
    {"Debuggable Application", "android:debuggable=\"true\""},
    {"Allow Backup Enabled", "android:allowBackup=\"true\""},
    {"Cleartext Traffic Enabled", "android:usesCleartextTraffic=\"true\""},
    {"Test Only Application", "android:testOnly=\"true\""},
    {"Grant URI Permissions", "android:grantUriPermissions=\"true\""},
    {"Shared User ID", "android:sharedUserId="},
    {"Custom Task Affinity", "android:taskAffinity="},
    {"Custom Process", "android:process="},
    {"Component Permission", "android:permission="},
    {"Read Permission", "android:readPermission="},
    {"Write Permission", "android:writePermission="},
    {"Content Provider Authority", "android:authorities="},
    {"Network Security Config", "android:networkSecurityConfig="},
    {"Legacy External Storage", "android:requestLegacyExternalStorage=\"true\""},
    {"Uses Permission", "<uses-permission"},
    {"Custom Permission", "<permission"},
    

};

typedef struct
{
    const char *name;
    const char *pattern;
} StringPattern;

StringPattern string_patterns[] =
{
    {"Google API Key", "AIza"},
    {"AWS Access Key", "AKIA"},
    {"AWS Temporary Key", "ASIA"},
    {"GitHub Personal Access Token", "ghp_"},
    {"GitHub OAuth Token", "gho_"},
    {"GitHub User Token", "ghu_"},
    {"GitHub Fine-grained Token", "github_pat_"},
    {"Stripe Secret Key", "sk_live_"},
    {"Stripe Publishable Key", "pk_live_"},
    {"Stripe Restricted Key", "rk_live_"},
    {"Slack Bot Token", "xoxb-"},
    {"Slack User Token", "xoxp-"},
    {"Discord Webhook", "discord.com/api/webhooks"},
    {"Slack Webhook", "hooks.slack.com"},
    {"Firebase URL", "firebaseio.com"},
    {"Firebase Storage", "firebasestorage.googleapis.com"},
    {"Amazon S3", "amazonaws.com"},
    {"Amazon S3 URL", "s3.amazonaws.com"},
    {"Azure Blob Storage", "blob.core.windows.net"},
    {"Passwd", "passwd"},
    {"Secret", "secret"},
    {"Token", "token"},
    {"API Key", "apikey"},
    {"API Key", "api_key"},
    {"Client Secret", "client_secret"},
    {"Client ID", "client_id"},
    {"Access Token", "access_token"},
    {"Refresh Token", "refresh_token"},
    {"Bearer Token", "bearer"},
    {"Admin", "admin"},
    {"JWT", "jwt"},
    {"OAuth", "oauth"},
    {"Private Key", "private_key"},
    {"Public Key", "public_key"},
    {"PEM Private Key", "BEGIN PRIVATE KEY"},
    {"RSA Private Key", "BEGIN RSA PRIVATE KEY"},
    {"EC Private Key", "BEGIN EC PRIVATE KEY"},
    {"FTP URL", "ftp://"},
    {"MongoDB URI", "mongodb://"},
    {"Redis URI", "redis://"},
    {"MySQL URI", "mysql://"},
    {"PostgreSQL URI", "postgres://"},
    {"facebook_app_id", "facebook_app_id"},
    {"fabric ApiKey", "io.fabric.ApiKey"},
    {"facebook_client_token", "facebook_client_token"},
    {"FACEBOOK_APP_ID", "com.facebook.sdk.ApplicationId"},
    {"FACEBOOK_CLIENT_TOKEN", "com.facebook.sdk.ClientToken"},
    {"PAYU_ID", "io.sentry.uuid.com.payu."},
    {"CLEVERTAP_ACCOUNT_ID", "CLEVERTAP_ACCOUNT_ID"},
    {"CLEVERTAP_TOKEN", "CLEVERTAP_TOKEN"},
    {"AD_MANAGER_APP_ID", "ca-app-pub"},
    {"clevertap_account_id", "clevertap_account_id"},
    {"clevertap_token", "clevertap_token"},
    {"CLEVERTAP_ACCOUNT_ID", "CLEVERTAP_ACCOUNT_ID"},
    {"CLEVERTAP_ACCOUNT_ID", "CLEVERTAP_ACCOUNT_ID"},
    
};

typedef struct
{
    const char *name;
    const char *pattern;
} RegexBucketsPattern;

RegexBucketsPattern Bucket[] = {
    // --- existing S3 / Firebase / GCP / Azure / misc (unchanged) ---
    {"S3_BUCKET", "([a-z0-9][a-z0-9\\-]{2,62}[a-z0-9])\\.s3\\.amazonaws\\.com"},
    {"S3_BUCKET", "s3\\.amazonaws\\.com/([a-z0-9][a-z0-9\\-]{2,62}[a-z0-9])"},
    {"S3_BUCKET", "s3-[a-z0-9-]+\\.amazonaws\\.com/([a-z0-9][a-z0-9\\-]{2,62}[a-z0-9])"},
    {"S3_BUCKET", "https?://([a-z0-9\\-]+)\\.s3[.-][a-z0-9-]*\\.amazonaws\\.com"},
    {"FIREBASE_DB", "https://([a-z0-9\\-]+)\\.firebaseio\\.com"},
    {"FIREBASE_DB", "https://([a-z0-9\\-]+)-default-rtdb\\.firebaseio\\.com"},
    {"FIREBASE_DB", "https://([a-z0-9\\-]+)-default-rtdb\\.[a-z0-9]+\\.firebasedatabase\\.app"},
    {"GCP_BUCKET", "storage\\.googleapis\\.com/([a-z0-9\\-_.]+)"},
    {"GCP_BUCKET", "([a-z0-9\\-_.]+)\\.storage\\.googleapis\\.com"},
    {"AZURE_BUCKET", "([a-z0-9\\-]+)\\.blob\\.core\\.windows\\.net"},
    {"AZURE_BUCKET", "([a-z0-9\\-]+)\\.file\\.core\\.windows\\.net"},
    {"AZURE_BUCKET", "([a-z0-9\\-]+)\\.queue\\.core\\.windows\\.net"},
    {"Firebase_STORAGE", "gs://[a-z0-9-]+\\.appspot\\.com"},
    {"MYSQL_URI", "mysql://[^:]+:[^@]+@[^/]+"},
    {"POSTGRES_URI", "postgres(ql)?://[^:]+:[^@]+@[^/]+"},
    {"MONGO_DB_URI", "mongodb(\\+srv)?://[^:]+:[^@]+@[^/]+"},
    {"DIGITALOCEAN_SPACES", "https?://[a-z0-9\\-]+\\.digitaloceanspaces\\.com/[a-z0-9/\\-]+"},
    {"CLOUDFRONT_URL", "https://[a-z0-9.-]+\\.cloudfront\\.net/[a-zA-Z0-9/._~?=&%\\-]*"},
    {"FIREBASE_PROJECT", "[a-z0-9\\-]+\\.firebaseio\\.com"},

    // --- ADDED: relational / SQL databases ---
    {"MSSQL_URI", "(sqlserver|mssql)://[^:]+:[^@]+@[^/]+"},
    {"MSSQL_CONN_STRING", "Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+;"},
    {"ORACLE_URI", "jdbc:oracle:thin:[^/]+/[^@]+@[^:]+:[0-9]+"},
    {"ORACLE_TNS", "\\([A-Za-z]+=\\(DESCRIPTION=.*?\\(SID=[A-Za-z0-9_]+\\)\\)\\)"},
    {"MARIADB_URI", "mariadb://[^:]+:[^@]+@[^/]+"},
    {"JDBC_GENERIC_URI", "jdbc:[a-z]+://[^:/\\s\"']+(:[0-9]+)?/[a-zA-Z0-9_\\-]+"},

    // --- ADDED: NoSQL / key-value / cache databases ---
    {"REDIS_URI", "redis(s)?://[^:]*:?[^@]*@?[^/\\s]+(:[0-9]+)?"},
    {"CASSANDRA_URI", "cassandra://[^:]+:[^@]+@[^/]+"},
    {"COUCHDB_URI", "https?://[^:]+:[^@]+@[^/]+\\.couchdb\\.com[^\\s\"']*"},
    {"ELASTICSEARCH_URI", "https?://[^:]+:[^@]+@[a-z0-9\\-\\.]+:9200"},
    {"DYNAMODB_ENDPOINT", "https://dynamodb\\.[a-z0-9-]+\\.amazonaws\\.com"},
    {"MEMCACHED_URI", "memcached://[^\\s:]+:[0-9]{2,5}"},
    {"NEO4J_URI", "(bolt|neo4j)(\\+s)?://[^:]+:[^@]+@[^/]+"},
    {"INFLUXDB_URI", "https?://[a-z0-9\\-\\.]+:8086/[a-zA-Z0-9_/\\-]*"},
    {"COSMOSDB_URI", "AccountEndpoint=https://[a-z0-9\\-]+\\.documents\\.azure\\.com[^;]*;AccountKey=[^;]+;"},
    {"RABBITMQ_URI", "amqp(s)?://[^:]+:[^@]+@[^/]+"},

    // --- ADDED: cloud-native DB-as-a-service ---
    {"FIRESTORE_URL", "https://firestore\\.googleapis\\.com/v1/projects/[a-z0-9\\-]+/databases/[a-zA-Z0-9_(default)]+"},
    {"SUPABASE_URI", "https://[a-z0-9]+\\.supabase\\.co"},
    {"SUPABASE_KEY", "eyJ[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9_\\-]+"}, // JWT-style anon/service key
    {"PLANETSCALE_URI", "mysql://[^:]+:[^@]+@[a-z0-9\\-\\.]+\\.psdb\\.cloud"},
    {"COCKROACHDB_URI", "postgresql://[^:]+:[^@]+@[a-z0-9\\-\\.]+(:[0-9]+)?/[a-zA-Z0-9_/\\-]*"},

    {"AIRTABLE_API_URI", "https://api\\.airtable\\.com/v0/[a-zA-Z0-9]+/[a-zA-Z0-9_%\\-]+(\\?[a-zA-Z0-9_=&%\\-]+)?"},
};

typedef struct
{
    const char *name;
    const char *pattern;
    const char *severity;
} RegexSecretPattern;

RegexSecretPattern secrets[] = {
    // --- existing (unchanged) ---
    {"AWS_ACCESS_KEY", "AKIA[0-9A-Z]{16}", "High"},
    {"AWS_SECRET_KEY", "aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "High"},
    {"GOOGLE_API_KEY", "AIza[0-9A-Za-z\\-_]{35}", "Medium"},
    {"FIREBASE_API_KEY", "AIza[0-9A-Za-z\\-_]{35}", "High"},
    {"GOOGLE_OAUTH", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com", "High"},
    {"JWT_TOKEN", "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", "High"},
    {"BEARER_TOKEN", "bearer[[:space:]]+[A-Za-z0-9._~+/-]{20,}", "High"},
    {"BASIC_AUTH_BASE64", "basic\\s+[A-Za-z0-9+/=]{16,}", "Medium"},
    {"STRIPE_LIVE_KEY", "sk_live_[0-9a-zA-Z]{24,}", "High"},
    {"STRIPE_TEST_KEY", "sk_test_[0-9a-zA-Z]{24,}", "Medium"},
    {"STRIPE_PUBLIC_KEY", "pk_live_[0-9a-zA-Z]{24,}", "Medium"},
    {"FACEBOOK_APP_SECRET", "facebook.{0,20}['\"][0-9a-f]{32}['\"]", "High"},
    {"TWITTER_CONSUMER_KEY", "twitter.{0,20}['\"][0-9a-zA-Z]{25,50}['\"]", "Medium"},
    {"GITHUB_TOKEN", "ghp_[A-Za-z0-9]{36}", "High"},
    {"SLACK_TOKEN", "xox[baprs]-[0-9A-Za-z\\-]{10,}", "High"},
    {"PRIVATE_KEY_HEADER", "-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "High"},
    {"HARDCODED_SECRET", "(secret|secret_key|secretkey)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]", "High"},
    {"HARDCODED_API_KEY", "(api_key|apikey|api-key)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]", "Medium"},

    // --- ADDED: GitHub / GitLab / Bitbucket family ---
    {"GITHUB_OAUTH_TOKEN", "gho_[A-Za-z0-9]{36}", "High"},
    {"GITHUB_APP_TOKEN", "(ghu|ghs)_[A-Za-z0-9]{36}", "High"},
    {"GITHUB_REFRESH_TOKEN", "ghr_[A-Za-z0-9]{36,76}", "High"},
    {"GITHUB_FINE_GRAINED_PAT", "github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", "High"},
    {"GITLAB_TOKEN", "glpat-[A-Za-z0-9\\-_]{20}", "High"},
    {"BITBUCKET_CLIENT_SECRET", "bitbucket.{0,20}['\"][0-9a-zA-Z]{32,40}['\"]", "Medium"},

    // --- ADDED: cloud providers (Azure / GCP / AWS extras) ---
    {"AZURE_STORAGE_KEY", "(AccountKey|account_key)=[A-Za-z0-9+/=]{60,}", "High"},
    {"AZURE_CONN_STRING", "DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,}", "High"},
    {"AZURE_SAS_TOKEN", "sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&[a-zA-Z0-9&=%]+sig=[A-Za-z0-9%]{20,}", "High"},
    {"AWS_SESSION_TOKEN", "aws.{0,20}session.{0,20}['\"][A-Za-z0-9/+=]{100,}['\"]", "High"},
    {"AWS_MWS_KEY", "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "High"},
    {"GCP_SERVICE_ACCOUNT_JSON", "\"type\"\\s*:\\s*\"service_account\"", "High"},
    {"GCP_PRIVATE_KEY_ID", "\"private_key_id\"\\s*:\\s*\"[0-9a-f]{40}\"", "High"},
    {"HEROKU_API_KEY", "heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "High"},

    // --- ADDED: messaging / push / chat platforms ---
    {"SLACK_WEBHOOK_URL", "https://hooks\\.slack\\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{24}", "High"},
    {"DISCORD_WEBHOOK_URL", "https://discord(app)?\\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\\-]{60,}", "High"},
    {"DISCORD_BOT_TOKEN", "[MNO][A-Za-z0-9]{23}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27}", "High"},
    {"TELEGRAM_BOT_TOKEN", "[0-9]{8,10}:AA[A-Za-z0-9_\\-]{33}", "High"},
    {"TWILIO_API_KEY", "SK[0-9a-fA-F]{32}", "High"},
    {"TWILIO_AUTH_TOKEN", "twilio.{0,20}['\"][0-9a-f]{32}['\"]", "High"},
    {"SENDGRID_API_KEY", "SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}", "High"},
    {"MAILGUN_API_KEY", "key-[0-9a-zA-Z]{32}", "High"},
    {"MAILCHIMP_API_KEY", "[0-9a-f]{32}-us[0-9]{1,2}", "Medium"},

    // --- ADDED: payment / fintech ---
    {"PAYPAL_BRAINTREE_TOKEN", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", "High"},
    {"SQUARE_ACCESS_TOKEN", "sq0atp-[0-9A-Za-z\\-_]{22}", "High"},
    {"SQUARE_OAUTH_SECRET", "sq0csp-[0-9A-Za-z\\-_]{43}", "High"},
    {"RAZORPAY_KEY", "rzp_(live|test)_[0-9a-zA-Z]{14}", "Medium"},
    {"PLAID_CLIENT_ID", "plaid.{0,20}client.{0,20}['\"][0-9a-f]{24}['\"]", "Medium"},
    {"PLAID_SECRET", "plaid.{0,20}secret.{0,20}['\"][0-9a-f]{30}['\"]", "High"},

    // --- ADDED: maps / sdk / misc third-party ---
    {"MAPBOX_TOKEN", "pk\\.eyJ[A-Za-z0-9_\\-]{50,}\\.[A-Za-z0-9_\\-]{20,}", "Medium"},
    {"ALGOLIA_API_KEY", "algolia.{0,20}['\"][0-9a-f]{32}['\"]", "Medium"},
    {"ALGOLIA_ADMIN_KEY", "algolia.{0,20}admin.{0,20}['\"][0-9a-f]{32}['\"]", "High"},
    {"SHOPIFY_ACCESS_TOKEN", "shpat_[0-9a-fA-F]{32}", "High"},
    {"SHOPIFY_SHARED_SECRET", "shpss_[0-9a-fA-F]{32}", "High"},
    {"NPM_TOKEN", "npm_[A-Za-z0-9]{36}", "High"},
    {"OPENAI_API_KEY", "sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "High"},
    {"ANTHROPIC_API_KEY", "sk-ant-[A-Za-z0-9\\-_]{90,}", "High"},
    {"DROPBOX_TOKEN", "sl\\.[A-Za-z0-9_\\-]{130,150}", "Medium"},
    {"NEW_RELIC_KEY", "NRAK-[A-Z0-9]{27}", "Medium"},
    {"DATADOG_API_KEY", "datadog.{0,20}['\"][0-9a-f]{32}['\"]", "Medium"},
    {"SENTRY_DSN", "https://[0-9a-f]{32}@[a-z0-9.]+\\.ingest\\.sentry\\.io/[0-9]+", "Medium"},

    // --- ADDED: crypto / wallets ---
    {"PRIVATE_KEY_HEADER_DSA", "-----BEGIN DSA PRIVATE KEY-----", "High"},
    {"PGP_PRIVATE_KEY_BLOCK", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "High"},

    // --- ADDED: generic catch-alls (high false-positive risk, kept Low/Medium) ---

    {"GENERIC_TOKEN_ASSIGN", "[a-zA-Z0-9_\\-]*token[a-zA-Z0-9_\\-]*\\s*[=:]\\s*['\"][0-9a-zA-Z\\-_.]{16,45}['\"]", "Low"},
    {"HARDCODED_ENCRYPTION_KEY", "(encryption_key|enc_key|cipher_key)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]", "High"},

};

typedef struct permission
{

    const char *permission;
    const char *definition;

} permission_data;

permission_data permission[] = {

    {"android.permission.READ_CONTACTS", "Can read all device contacts"},
    {"android.permission.WRITE_CONTACTS", "Can modify/delete contacts"},
    {"android.permission.READ_CALL_LOG", "Can read call history"},
    {"android.permission.READ_SMS", "Can read all SMS messages"},
    {"android.permission.RECEIVE_SMS", "Can intercept incoming SMS (e.g., 2FA codes)"},
    {"android.permission.SEND_SMS", "Can send SMS (potential financial abuse)"},
    {"android.permission.RECORD_AUDIO", "Microphone access — potential surveillance"},
    {"android.permission.CAMERA", "Camera access"},
    {"android.permission.ACCESS_FINE_LOCATION", "Precise GPS tracking"},
    {"android.permission.ACCESS_BACKGROUND_LOCATION", "Background location tracking"},
    {"android.permission.READ_EXTERNAL_STORAGE", "Can read all files on device"},
    {"android.permission.WRITE_EXTERNAL_STORAGE", "Can write/delete files on device"},
    {"android.permission.PROCESS_OUTGOING_CALLS", "Can intercept/redirect outgoing calls"},
    {"android.permission.GET_ACCOUNTS", "Can enumerate all accounts on device"},
    {"android.permission.USE_CREDENTIALS", "Can use account credentials"},
    {"android.permission.MANAGE_ACCOUNTS", "Can add/remove/modify accounts"},
    {"android.permission.BLUETOOTH_ADMIN", "Can manage Bluetooth connections"},
    {"android.permission.CHANGE_NETWORK_STATE", "Can change WiFi/mobile data state"},
    {"android.permission.NFC", "NFC access — potential contactless payment abuse"},
    {"android.permission.SYSTEM_ALERT_WINDOW", "Can draw overlays — tapjacking/phishing risk"},
    {"android.permission.BIND_ACCESSIBILITY_SERVICE", "Accessibility abuse — can read screen, click UI"},
    {"android.permission.REQUEST_INSTALL_PACKAGES", "Can silently install apps"},
    {"android.permission.FOREGROUND_SERVICE", "Can run persistent background service"},

};

#endif