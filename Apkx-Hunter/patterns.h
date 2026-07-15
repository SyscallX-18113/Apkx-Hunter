#ifndef PATTERNS_H
#define PATTERNS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

const char *patterns[] = {
 
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

    "/health",
    "/metrics",
    "/trace",
    "/heapdump",
    "/jmx",
    "/logs",
    "/dump",

    "/graphql",
    "/gql",
    "/__schema",
    "/playground",
    "/graphiql",
    "/introspection",

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

    "/account",
    "/customer",
    "/preferences",
    "/avatar",

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
    {"CLEVERTAP_TOKEN", "CLEVERTAP_TOKEN"},
    {"AD_MANAGER_APP_ID", "ca-app-pub"},
    {"clevertap_account_id", "clevertap_account_id"},
    {"clevertap_token", "clevertap_token"},
    {"CLEVERTAP_ACCOUNT_ID", "CLEVERTAP_ACCOUNT_ID"},

    
};

typedef struct
{
    const char *name;
    const char *pattern;
} RegexBucketsPattern;

RegexBucketsPattern Bucket[] = {

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

    {"MSSQL_URI", "(sqlserver|mssql)://[^:]+:[^@]+@[^/]+"},
    {"MSSQL_CONN_STRING", "Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+;"},
    {"ORACLE_URI", "jdbc:oracle:thin:[^/]+/[^@]+@[^:]+:[0-9]+"},
    {"ORACLE_TNS", "\\([A-Za-z]+=\\(DESCRIPTION=.*?\\(SID=[A-Za-z0-9_]+\\)\\)\\)"},
    {"MARIADB_URI", "mariadb://[^:]+:[^@]+@[^/]+"},
    {"JDBC_GENERIC_URI", "jdbc:[a-z]+://[^:/\\s\"']+(:[0-9]+)?/[a-zA-Z0-9_\\-]+"},

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

    {"GITHUB_OAUTH_TOKEN", "gho_[A-Za-z0-9]{36}", "High"},
    {"GITHUB_APP_TOKEN", "(ghu|ghs)_[A-Za-z0-9]{36}", "High"},
    {"GITHUB_REFRESH_TOKEN", "ghr_[A-Za-z0-9]{36,76}", "High"},
    {"GITHUB_FINE_GRAINED_PAT", "github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", "High"},
    {"GITLAB_TOKEN", "glpat-[A-Za-z0-9\\-_]{20}", "High"},
    {"BITBUCKET_CLIENT_SECRET", "bitbucket.{0,20}['\"][0-9a-zA-Z]{32,40}['\"]", "Medium"},

    {"AZURE_STORAGE_KEY", "(AccountKey|account_key)=[A-Za-z0-9+/=]{60,}", "High"},
    {"AZURE_CONN_STRING", "DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,}", "High"},
    {"AZURE_SAS_TOKEN", "sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&[a-zA-Z0-9&=%]+sig=[A-Za-z0-9%]{20,}", "High"},
    {"AWS_SESSION_TOKEN", "aws.{0,20}session.{0,20}['\"][A-Za-z0-9/+=]{100,}['\"]", "High"},
    {"AWS_MWS_KEY", "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "High"},
    {"GCP_SERVICE_ACCOUNT_JSON", "\"type\"\\s*:\\s*\"service_account\"", "High"},
    {"GCP_PRIVATE_KEY_ID", "\"private_key_id\"\\s*:\\s*\"[0-9a-f]{40}\"", "High"},
    {"HEROKU_API_KEY", "heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "High"},

    {"SLACK_WEBHOOK_URL", "https://hooks\\.slack\\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{24}", "High"},
    {"DISCORD_WEBHOOK_URL", "https://discord(app)?\\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\\-]{60,}", "High"},
    {"DISCORD_BOT_TOKEN", "[MNO][A-Za-z0-9]{23}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27}", "High"},
    {"TELEGRAM_BOT_TOKEN", "[0-9]{8,10}:AA[A-Za-z0-9_\\-]{33}", "High"},
    {"TWILIO_API_KEY", "SK[0-9a-fA-F]{32}", "High"},
    {"TWILIO_AUTH_TOKEN", "twilio.{0,20}['\"][0-9a-f]{32}['\"]", "High"},
    {"SENDGRID_API_KEY", "SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43}", "High"},
    {"MAILGUN_API_KEY", "key-[0-9a-zA-Z]{32}", "High"},
    {"MAILCHIMP_API_KEY", "[0-9a-f]{32}-us[0-9]{1,2}", "Medium"},

    {"PAYPAL_BRAINTREE_TOKEN", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", "High"},
    {"SQUARE_ACCESS_TOKEN", "sq0atp-[0-9A-Za-z\\-_]{22}", "High"},
    {"SQUARE_OAUTH_SECRET", "sq0csp-[0-9A-Za-z\\-_]{43}", "High"},
    {"RAZORPAY_KEY", "rzp_(live|test)_[0-9a-zA-Z]{14}", "Medium"},
    {"PLAID_CLIENT_ID", "plaid.{0,20}client.{0,20}['\"][0-9a-f]{24}['\"]", "Medium"},
    {"PLAID_SECRET", "plaid.{0,20}secret.{0,20}['\"][0-9a-f]{30}['\"]", "High"},

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

    {"PRIVATE_KEY_HEADER_DSA", "-----BEGIN DSA PRIVATE KEY-----", "High"},
    {"PGP_PRIVATE_KEY_BLOCK", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "High"},

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


typedef struct
{
    const char *name;
    const char *pattern;
    const char *severity;
    const char *description;
} masvs_pattern;

masvs_pattern masvs_patterns[] =
{
    { "Weak Hash Algorithm", "MessageDigest.getInstance(\"MD5\")", "HIGH", "MD5 is considered cryptographically broken." },
    { "Weak Hash Algorithm", "MessageDigest.getInstance(\"SHA-1\")", "HIGH", "SHA-1 is deprecated for security-sensitive applications." },
    { "Weak Hash Algorithm", "MessageDigest.getInstance(\"MD2\")", "HIGH", "MD2 is an obsolete and insecure hash algorithm." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"DES\")", "CRITICAL", "DES is a broken cipher with a trivially small key space." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"DESede\")", "HIGH", "Triple DES (3DES) is deprecated and considered weak." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"RC2\")", "HIGH", "RC2 is a legacy weak block cipher." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"RC4\")", "CRITICAL", "RC4 is a broken stream cipher, vulnerable to key-recovery attacks." },
    { "Insecure Cipher Mode", "Cipher.getInstance(\"AES/ECB", "HIGH", "ECB mode does not provide semantic security and leaks data patterns." },
    { "Insecure Cipher Mode", "AES/ECB/PKCS5Padding", "HIGH", "ECB mode reveals patterns in encrypted data; use CBC/GCM instead." },
    { "Insecure Cipher Mode", "AES/ECB/NoPadding", "HIGH", "ECB mode with no padding is insecure for block encryption." },
    { "No Padding Used", "Cipher.getInstance(\"AES/CBC/NoPadding\")", "MEDIUM", "Missing padding scheme can lead to padding oracle or malleability issues." },
    { "Hardcoded Encryption Key", "SecretKeySpec(", "HIGH", "Potential hardcoded key material passed to SecretKeySpec." },
    { "Hardcoded IV", "IvParameterSpec(", "MEDIUM", "Static or hardcoded IVs undermine cipher security guarantees." },
    { "Weak Random Number Generator", "new Random(", "HIGH", "java.util.Random is not cryptographically secure." },
    { "Weak Random Number Generator", "Math.random(", "HIGH", "Math.random() is not suitable for security-sensitive operations." },
    { "Predictable Seed", "setSeed(", "MEDIUM", "Setting an explicit seed can make random values predictable." },
    { "Weak Key Generation", "KeyGenerator.getInstance(\"DES\")", "CRITICAL", "DES-based key generation is insecure." },
    { "Weak Key Size", "KeyPairGenerator.initialize(512", "CRITICAL", "512-bit RSA keys are trivially breakable." },
    { "Weak Key Size", "KeyPairGenerator.initialize(1024", "HIGH", "1024-bit RSA keys are considered weak by modern standards." },
    { "Insecure PBE Algorithm", "PBEWithMD5AndDES", "HIGH", "Password-based encryption using MD5/DES is weak." },
    { "Weak KDF Iteration Count", "PBEKeySpec(", "MEDIUM", "Verify iteration count is sufficiently high to resist brute force." },
    
    { "Custom Crypto Implementation", "class MyCipher", "MEDIUM", "Custom cryptographic implementations are error-prone; prefer vetted libraries." },
    
    { "Insecure SSLContext", "SSLContext.getInstance(\"SSL\")", "HIGH", "Legacy SSL protocol is insecure; use TLS 1.2+." },
    { "Insecure Protocol Version", "SSLContext.getInstance(\"TLSv1\")", "MEDIUM", "TLS 1.0 is deprecated and vulnerable to known attacks." },
    { "Insecure Protocol Version", "SSLContext.getInstance(\"TLSv1.1\")", "MEDIUM", "TLS 1.1 is deprecated." },
    { "Weak Signature Algorithm", "Signature.getInstance(\"MD5withRSA\")", "HIGH", "MD5-based signatures are vulnerable to collision attacks." },
    { "Weak Signature Algorithm", "Signature.getInstance(\"SHA1withRSA\")", "MEDIUM", "SHA1-based signatures are deprecated." },
    { "Kotlin Weak Hash", "MessageDigest.getInstance(\"MD5\").digest", "HIGH", "Kotlin usage of MD5 digest, cryptographically broken." },
    
// certificate_pinning_patterns
    { "Missing Certificate Pinning", "X509TrustManager", "MEDIUM", "Custom TrustManager present; verify certificate pinning is enforced." },
    { "Trust All Certificates", "checkServerTrusted", "HIGH", "Verify this does not blindly trust all server certificates." },
    { "Trust All Certificates", "checkClientTrusted", "HIGH", "Verify this does not blindly trust all client certificates." },
    { "Empty TrustManager Implementation", "public void checkServerTrusted(X509Certificate[] chain, String authType) {}", "CRITICAL", "Empty implementation disables certificate validation entirely." },
    
    { "OkHttp Pinning Disabled", "CertificatePinner.NONE", "CRITICAL", "Certificate pinning explicitly disabled in OkHttp." },
 
    { "Debug Overrides Enabled", "<debug-overrides", "MEDIUM", "Debug overrides may allow user-added CAs, weakening pinning in debug builds." },
    { "Cleartext Traffic Permitted", "cleartextTrafficPermitted=\"true\"", "HIGH", "Cleartext traffic permitted, bypassing TLS protections." },
    { "AndroidManifest Cleartext Flag", "android:usesCleartextTraffic=\"true\"", "HIGH", "Application explicitly allows cleartext (unencrypted) traffic." },
    { "Custom HostnameVerifier", "HostnameVerifier", "MEDIUM", "Custom hostname verifier present; verify it correctly validates hostnames." },
    { "Allow All Hostname Verifier", "ALLOW_ALL_HOSTNAME_VERIFIER", "CRITICAL", "Hostname verification is completely disabled." },
    { "Insecure Hostname Verifier", "setHostnameVerifier((hostname, session) -> true)", "CRITICAL", "Hostname verification lambda always returns true, disabling checks." },
    { "OkHttp Unsafe Hostname Verifier", "HostnameVerifier() { public boolean verify(String hostname, SSLSession session) { return true; } }", "CRITICAL", "Hostname verifier unconditionally accepts all hostnames." },
    
    { "Certificate Transparency Bypass", "setCTEnabled(false)", "MEDIUM", "Certificate Transparency verification disabled." },
    
// root_detection_patterns

 
    { "Dangerous Props Check", "ro.debuggable", "MEDIUM", "Checks debuggable system property, which should be 0 on production devices." },
    { "Dangerous Props Check", "ro.secure", "MEDIUM", "Checks ro.secure system property for root/security posture." },
 
    { "Xposed Framework Detection", "de.robv.android.xposed", "MEDIUM", "Checks for Xposed Framework, which can hook and modify app behavior." },
    { "Xposed Bridge Detection", "XposedBridge", "MEDIUM", "Detects presence of XposedBridge class used by Xposed modules." },
    { "Frida Detection", "frida-server", "MEDIUM", "Checks for Frida server process, a dynamic instrumentation toolkit." },
    
    { "Runtime Exec Root Check", "Runtime.getRuntime().exec(\"su\")", "MEDIUM", "Executes su via Runtime.exec to test root access." },
 
    { "Su Binary Check", "/data/local/su", "MEDIUM", "Checks for su binary in /data/local, a common root indicator path." },
    { "Su Binary Check", "/data/local/bin/su", "MEDIUM", "Checks for su binary in /data/local/bin, a common root indicator path." },
    { "Su Binary Check", "/data/local/xbin/su", "MEDIUM", "Checks for su binary in /data/local/xbin, a common root indicator path." },
    { "Su Binary Check", "/sbin/su", "MEDIUM", "Checks for su binary in /sbin, common on rooted devices." },
    { "Su Binary Check", "/su/bin/su", "MEDIUM", "Checks for su binary under a dedicated /su mount point used by some root solutions." },
    { "Su Binary Check", "/system/bin/su", "MEDIUM", "Checks for su binary in /system/bin, the standard root indicator path." },
    { "Su Binary Check", "/system/bin/.ext/su", "MEDIUM", "Checks for su binary hidden in /system/bin/.ext, used to evade basic root checks." },
    { "Su Binary Check", "/system/bin/failsafe/su", "MEDIUM", "Checks for su binary in the failsafe boot path, an alternate root indicator." },
    { "Su Binary Check", "/system/sd/xbin/su", "MEDIUM", "Checks for su binary on SD-mounted xbin path, a legacy root indicator." },
    { "Su Binary Check", "/system/usr/we-need-root/su", "MEDIUM", "Checks for su binary in a known custom-ROM root placement path." },
    { "Su Binary Check", "/system/xbin/su", "MEDIUM", "Checks for su binary in /system/xbin, a standard root indicator path." },
    { "Su Binary Check", "/cache/su", "MEDIUM", "Checks for su binary in /cache, an atypical but known root placement path." },
    { "Su Binary Check", "/data/su", "MEDIUM", "Checks for su binary directly under /data, a root indicator path." },
    { "Su Binary Check", "/dev/su", "MEDIUM", "Checks for su binary under /dev, an atypical root placement path." },
// anti_debugging_patterns

 
    { "Application Debuggable Flag", "ApplicationInfo.FLAG_DEBUGGABLE", "MEDIUM", "Checks the application's debuggable flag at runtime." },
    { "Manifest Debuggable Flag", "android:debuggable=\"true\"", "CRITICAL", "Application is explicitly marked debuggable in the manifest." },
    { "Ptrace Anti-Debug", "ptrace(PTRACE_TRACEME", "MEDIUM", "Uses ptrace self-tracing to prevent a debugger from attaching." },
    { "TracerPid Check", "TracerPid", "MEDIUM", "Inspects /proc/self/status TracerPid field to detect debuggers." },
 
    { "JDWP Detection", "jdwp", "MEDIUM", "Checks for Java Debug Wire Protocol activity, indicating a debugger." },
    { "Native Anti-Debug", "__ptrace_traceme", "MEDIUM", "Native-level ptrace anti-debugging technique." },
 
    { "Anti Frida Detection", "gum-js-loop", "MEDIUM", "Checks for Frida's internal thread name used during instrumentation." },
    { "Anti Frida Detection", "frida_agent", "MEDIUM", "Checks for Frida agent library presence." },
    { "Anti Frida Detection", "linjector", "MEDIUM", "Checks for linjector, a library injection tool used with Frida." },
    
//  anti_tamper_patterns

 
    { "APK Signature Hash Check", "signatures[0].hashCode()", "MEDIUM", "Compares signature hash to detect resigned/tampered APKs." },
 
    { "Hooking Framework Detection", "com.saurik.substrate", "MEDIUM", "Detects Cydia Substrate hooking framework." },
    { "Hooking Framework Detection", "de.robv.android.xposed.XposedHelpers", "MEDIUM", "Detects Xposed hooking helper classes." },
 
// sharedpreferences_patterns

    { "World Readable Mode", "MODE_WORLD_READABLE", "CRITICAL", "Deprecated and insecure mode allowing any app to read preferences." },
    { "World Writable Mode", "MODE_WORLD_WRITABLE", "CRITICAL", "Deprecated and insecure mode allowing any app to modify preferences." },
    { "Plaintext SharedPreferences", "getSharedPreferences(", "MEDIUM", "Verify sensitive data is not stored in plaintext SharedPreferences." },
    
    { "Storing Sensitive Data", "putString(\"password\"", "CRITICAL", "Potential storage of a password in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"token\"", "HIGH", "Potential storage of an auth token in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"api_key\"", "HIGH", "Potential storage of an API key in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"secret\"", "HIGH", "Potential storage of a secret value in plaintext SharedPreferences." },
    
    { "Kotlin SharedPreferences", "getSharedPreferences(", "MEDIUM", "Verify Kotlin SharedPreferences usage does not store sensitive data." },
 
// sqlite_patterns

    { "SQL Injection Risk", "rawQuery(", "HIGH", "Raw SQL query usage; verify parameters are not concatenated unsafely." },
    { "SQL Injection Risk", "execSQL(", "HIGH", "Direct SQL execution; verify inputs are parameterized to prevent injection." },
    { "String Concatenation in Query", "\"SELECT * FROM \" +", "HIGH", "String concatenation in SQL queries is vulnerable to SQL injection." },
    { "Unencrypted SQLite Database", "SQLiteDatabase.openOrCreateDatabase(", "MEDIUM", "Verify database is encrypted (e.g., via SQLCipher) if storing sensitive data." },
    { "Unencrypted SQLite Database", "SQLiteOpenHelper", "MEDIUM", "SQLiteOpenHelper subclass; verify sensitive data is encrypted at rest." },
 
    { "Hardcoded DB Password", "openOrCreateDatabase(", "MEDIUM", "Verify database password/key is not hardcoded in source." },
    
    { "Database Backup Enabled", "android:allowBackup=\"true\"", "MEDIUM", "Allows database files to be extracted via adb backup on unsecured devices." },
    
    { "Room Raw Query", "@RawQuery", "MEDIUM", "Room raw query annotation; verify inputs are not vulnerable to injection." },
    
    { "Database File World Readable", "MODE_WORLD_READABLE", "CRITICAL", "Database file created with insecure world-readable permissions." },

// external_storage_patterns

    { "External Storage Write", "getExternalStorageDirectory()", "HIGH", "Writing to external storage exposes data to any app with storage permission." },
    { "External Files Dir", "getExternalFilesDir(", "MEDIUM", "Verify sensitive data is not written to app-specific external storage." },
    { "External Cache Dir", "getExternalCacheDir(", "MEDIUM", "Verify sensitive data is not cached on external storage." },
    { "Legacy External Storage", "requestLegacyExternalStorage=\"true\"", "MEDIUM", "Legacy external storage access bypasses scoped storage protections." },
    { "Write External Storage Permission", "WRITE_EXTERNAL_STORAGE", "MEDIUM", "Permission allows writing to shared external storage." },
    { "Read External Storage Permission", "READ_EXTERNAL_STORAGE", "MEDIUM", "Permission allows reading from shared external storage." },
    { "MANAGE_EXTERNAL_STORAGE Permission", "MANAGE_EXTERNAL_STORAGE", "HIGH", "Broad permission granting access to all files on external storage." },
    { "FileOutputStream to External Path", "FileOutputStream(\"/sdcard/", "HIGH", "Direct write to /sdcard path; verify no sensitive data is exposed." },
    { "Hardcoded SD Card Path", "/storage/emulated/0/", "MEDIUM", "Hardcoded external storage path detected." },
 
    { "World Readable File Creation", "openFileOutput(", "MEDIUM", "Verify file mode does not use MODE_WORLD_READABLE/WRITEABLE." },
    { "Scoped Storage Bypass", "Environment.isExternalStorageLegacy()", "MEDIUM", "Checks for legacy storage bypass of scoped storage restrictions." },

 
// dynamic_code_loading_patterns
    { "DexClassLoader Usage", "DexClassLoader(", "HIGH", "Dynamically loads external DEX code, a common malware/evasion technique." },
    { "PathClassLoader Usage", "PathClassLoader(", "MEDIUM", "Loads classes from a specified path; verify source is trusted." },
    { "InMemoryDexClassLoader Usage", "InMemoryDexClassLoader(", "HIGH", "Loads DEX bytecode directly from memory, evading static file analysis." },
    { "DexFile Loading", "DexFile.loadDex(", "HIGH", "Explicit dynamic loading of DEX files at runtime." },
    { "DexFile Class Loading", "new DexFile(", "HIGH", "Instantiates a DexFile object for dynamic code loading." },
    { "Native Library Dynamic Load", "System.load(", "MEDIUM", "Loads a native library from an absolute path at runtime." },
    
    { "Runtime Class Definition", "defineClass(", "HIGH", "Defines a class dynamically from raw bytecode at runtime." },
    { "Kotlin Dynamic Class Loading", "URLClassLoader(", "MEDIUM", "Loads classes dynamically from a URL, potential remote code execution vector." },
    { "APK Patch Loading", "loadDex(", "HIGH", "Loads a DEX patch/plugin dynamically, potential hot-patching risk." },
    
    { "Plugin Framework Loading", "DL.loadApk(", "MEDIUM", "Dynamic plugin/APK loading framework usage detected." },

 
// reflection_patterns

    { "Reflection Accessibility Bypass", "setAccessible(true)", "HIGH", "Bypasses Java access control checks, allowing access to private members." },
    { "Reflection Based Instantiation", "newInstance()", "MEDIUM", "Dynamically instantiates an object, potentially bypassing constructor checks." },
    { "Hidden API Access via Reflection", "getDeclaredMethods()", "MEDIUM", "Enumerates all declared methods, sometimes used to access hidden APIs." },
    { "Reflection on System Classes", "Class.forName(\"android.os", "HIGH", "Reflective access to internal Android OS classes, often used to bypass restrictions." },

// runtime_command_execution_patterns
    { "Runtime Exec Call", "Runtime.getRuntime().exec(", "HIGH", "Executes an OS-level command; verify inputs are not user-controlled." },
    { "ProcessBuilder Usage", "ProcessBuilder(", "HIGH", "Spawns a new OS process; verify command arguments are sanitized." },
    { "Shell Command Execution", "/system/bin/sh", "HIGH", "Directly invokes a shell, high risk of command injection if input is unsanitized." },
    { "Shell Command Execution", "/bin/sh -c", "HIGH", "Invokes shell with -c flag to execute arbitrary command strings." },
    { "Exec Native Function", "system(", "CRITICAL", "Native system() call; verify no untrusted input reaches the command string." },
    { "Native Exec Function", "execve(", "HIGH", "Native execve() syscall for process execution." },
    { "Native Popen Function", "popen(", "HIGH", "Native popen() call executes a command via shell, injection risk if unsanitized." },
    { "Command Injection Risk", "exec(\"su -c", "CRITICAL", "Executes elevated shell commands via su, high risk if input is unsanitized." },
    { "Kotlin Runtime Exec", "Runtime.getRuntime().exec(arrayOf(", "HIGH", "Kotlin usage of Runtime.exec with argument array." },

// webview_security_patterns

    { "JavaScript Enabled", "setJavaScriptEnabled(true)", "MEDIUM", "Enables JavaScript execution in WebView, increasing XSS attack surface." },
    { "JavaScript Interface Exposure", "addJavascriptInterface(", "HIGH", "Exposes Java objects to JavaScript, risk of remote code execution pre-API 17." },
    { "File Access Enabled", "setAllowFileAccess(true)", "MEDIUM", "Allows WebView to access local file system resources." },
    { "Universal File Access", "setAllowUniversalAccessFromFileURLs(true)", "CRITICAL", "Allows universal access from file URLs, a severe security risk." },
    { "File Access From File URLs", "setAllowFileAccessFromFileURLs(true)", "HIGH", "Allows file-scheme pages to access other file-scheme resources." },
    { "Mixed Content Allowed", "setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW)", "HIGH", "Allows insecure HTTP content to load within an HTTPS WebView page." },
    { "WebView Debugging Enabled", "setWebContentsDebuggingEnabled(true)", "MEDIUM", "Enables remote WebView debugging, should be disabled in production." },
    { "Insecure SSL Error Handling", "onReceivedSslError", "HIGH", "Custom SSL error handler; verify it does not blindly proceed on errors." },
    { "Ignore SSL Errors", "handler.proceed()", "CRITICAL", "Proceeds despite SSL errors, bypassing certificate validation in WebView." },
    { "Load URL From Intent", "loadUrl(getIntent()", "HIGH", "Loads a URL sourced from an external Intent, potential injection vector." },
    
    { "Safe Browsing Disabled", "setSafeBrowsingEnabled(false)", "MEDIUM", "Disables Google Safe Browsing protection in WebView." },
    { "Kotlin WebView JS Interface", "addJavascriptInterface(this,", "HIGH", "Kotlin WebView exposes an interface object to JavaScript context." },
    { "WebView Content Provider Access", "setAllowContentAccess(true)", "MEDIUM", "Allows WebView to access content:// URIs, verify provider exposure." },


// ssl_validation_patterns
    { "Custom TrustManager Bypass", "public void checkServerTrusted", "HIGH", "Custom server trust validation; verify it performs proper chain validation." },
    { "SSLSocketFactory Override", "setSSLSocketFactory(", "MEDIUM", "Custom SSLSocketFactory; verify it does not weaken TLS validation." },
    { "TrustAllSSLSocketFactory", "TrustAllSSLSocketFactory", "CRITICAL", "Custom socket factory named to trust all certificates unconditionally." },
    { "SSL Error Ignored (WebView)", "SslErrorHandler", "HIGH", "Handles SSL errors; verify errors are not silently ignored." },
    { "Insecure OkHttp SSL Config", "sslSocketFactory(", "MEDIUM", "Custom SSL socket factory configured in OkHttp; verify trust manager validity." },
    { "Insecure Volley HurlStack", "HurlStack(null,", "MEDIUM", "Volley HurlStack with custom SSL factory, verify secure configuration." },
    { "Naive Trust Manager", "NaiveTrustManager", "CRITICAL", "Trust manager implementation name suggests unconditional trust." },
    { "Empty Certificate Chain Check", "return new X509Certificate[]{}", "HIGH", "Returns empty certificate chain, potentially bypassing validation logic." },
    { "SSL Pinning Bypass Comment", "// TODO: implement SSL pinning", "MEDIUM", "Code comment indicates SSL pinning is not yet implemented." },
    { "Apache SSL All Trusting", "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER", "CRITICAL", "Apache HttpClient configured to trust all hostnames unconditionally." },

// native_library_loading_patterns

    { "Native Library Load By Path", "System.load(", "MEDIUM", "Loads a native library from an absolute file path at runtime." },
 
    { "Dynamic Library Open (Native)", "dlopen(", "MEDIUM", "Native dynamic library loading via dlopen(); verify loaded library source." },
    { "Dynamic Symbol Resolution", "dlsym(", "MEDIUM", "Resolves a symbol from a dynamically loaded library at runtime." },
    
    { "Native Library From External Storage", "loadLibrary(\"/sdcard/", "CRITICAL", "Loads a native library from external storage, a severe code injection risk." },
 
};

masvs_pattern network_security_patterns[] =
{

    { "Cleartext HTTP URL", "http://", "MEDIUM", "Hardcoded cleartext HTTP URL detected; data transmitted is unencrypted." },
 
    { "OkHttp Logging Interceptor", "HttpLoggingInterceptor", "MEDIUM", "Logging interceptor may leak sensitive request/response data in logs." },
    { "OkHttp Logging Level Body", "Level.BODY", "MEDIUM", "Full request/response body logging risks exposing sensitive data." },
    { "Retrofit Insecure Base URL", "http://", "MEDIUM", "Retrofit configured with a cleartext base URL." },
    { "Apache HttpClient Usage", "DefaultHttpClient(", "MEDIUM", "Deprecated Apache HttpClient; verify secure configuration." },
    { "Disabled Certificate Validation", "ALLOW_ALL_HOSTNAME_VERIFIER", "CRITICAL", "All-permissive hostname verifier disables TLS hostname validation." },
    { "Insecure Socket Connection", "new Socket(", "MEDIUM", "Raw socket connection; verify TLS/SSL is used for sensitive data." },
    { "Insecure Trust Manager Array", "new TrustManager[]{new X509TrustManager()", "CRITICAL", "Custom TrustManager array potentially bypassing certificate checks." },
    
    { "WebSocket Insecure Scheme", "ws://", "MEDIUM", "Unencrypted WebSocket connection (ws://) detected instead of wss://." },
    
    { "FTP Cleartext Protocol", "ftp://", "MEDIUM", "Unencrypted FTP protocol reference detected." },
};


char *false_positives[] = {
    "http://schemas.android.com/apk/res/android",
    "http://schemas.xmlsoap.org/wsdl/",
    "http://www.w3.org/2000/09/xmldsig#",
    "http://www.w3.org/2001/XMLSchema",
    "http://www.w3.org/XML/1998/namespace",
    "http://schemas.microsoft.com/",
    "http://www.w3.org/TR/REC-html40",
    "http://java.sun.com/",
    "http://xml.org/sax/",
    "http://apache.org/xml/"
};



#endif
