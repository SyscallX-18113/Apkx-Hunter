
#include "patterns.h"


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
    {"API Key", "apikey"},
    {"API Key", "api_key"},
    {"Client Secret", "client_secret"},
    {"Client ID", "client_id"},
    {"Access Token", "access_token"},
    {"Refresh Token", "refresh_token"},
    {"Bearer Token", "bearer"},
    {"JWT", "jwt"},
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


masvs_pattern weak_networks[] =
{
 
    { "Weak Hash Algorithm", "MessageDigest.getInstance(\"MD5\")", "HIGH", "MD5 is considered cryptographically broken." },
    { "Weak Hash Algorithm", "MessageDigest.getInstance(\"SHA-1\")", "HIGH", "SHA-1 is deprecated for security-sensitive applications." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"DES\")", "CRITICAL", "DES is a broken cipher with a trivially small key space." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"DESede\")", "HIGH", "Triple DES (3DES) is deprecated and considered weak." },
    { "Weak Cipher Algorithm", "Cipher.getInstance(\"RC4\")", "CRITICAL", "RC4 is a broken stream cipher, vulnerable to key-recovery attacks." },
    { "Insecure Cipher Mode", "Cipher.getInstance(\"AES/ECB", "HIGH", "ECB mode does not provide semantic security and leaks data patterns." },
    { "Weak Key Size", "KeyPairGenerator.initialize(512", "CRITICAL", "512-bit RSA keys are trivially breakable." },
    { "Weak Key Size", "KeyPairGenerator.initialize(1024", "HIGH", "1024-bit RSA keys are considered weak by modern standards." },
    { "Insecure PBE Algorithm", "PBEWithMD5AndDES", "HIGH", "Password-based encryption using MD5/DES is weak." },
    { "Insecure Cipher Mode", "Cipher.getInstance(\"AES\")", "HIGH", "Bare \"AES\" defaults to AES/ECB on Android, which leaks data patterns." },
    { "Hardcoded Encryption Key", "new SecretKeySpec(\"", "HIGH", "Encryption key built from a hardcoded string literal." },
    { "Hardcoded IV", "IvParameterSpec(new byte[", "HIGH", "Static/zero IV defeats CBC/GCM security guarantees." },
    { "Weak Random Number Generator", "SecureRandom.getInstance(\"SHA1PRNG\")", "MEDIUM", "SHA1PRNG is deprecated and can be predictable when seeded manually." },
 
    { "Insecure SSLContext", "SSLContext.getInstance(\"SSL\")", "HIGH", "Legacy SSL protocol is insecure; use TLS 1.2+." },
    { "Insecure Protocol Version", "SSLContext.getInstance(\"TLSv1\")", "MEDIUM", "TLS 1.0 is deprecated and vulnerable to known attacks." },
    { "Insecure Protocol Version", "SSLContext.getInstance(\"TLSv1.1\")", "MEDIUM", "TLS 1.1 is deprecated." },
    { "Weak Signature Algorithm", "Signature.getInstance(\"MD5withRSA\")", "HIGH", "MD5-based signatures are vulnerable to collision attacks." },
 
    { "Empty TrustManager Implementation", "public void checkServerTrusted(X509Certificate[] chain, String authType) {}", "CRITICAL", "Empty implementation disables certificate validation entirely." },
    { "Cleartext Traffic Permitted", "cleartextTrafficPermitted=\"true\"", "HIGH", "Cleartext traffic permitted, bypassing TLS protections." },
    { "Allow All Hostname Verifier", "ALLOW_ALL_HOSTNAME_VERIFIER", "CRITICAL", "Hostname verification is completely disabled." },
    { "Insecure Hostname Verifier", "setHostnameVerifier((hostname, session) -> true)", "CRITICAL", "Hostname verification lambda always returns true, disabling checks." },
    { "TrustAllSSLSocketFactory", "TrustAllSSLSocketFactory", "CRITICAL", "Custom socket factory named to trust all certificates unconditionally." },
    { "Naive Trust Manager", "NaiveTrustManager", "CRITICAL", "Trust manager implementation name suggests unconditional trust." },
    { "Allow All Hostname Verifier", "AllowAllHostnameVerifier", "CRITICAL", "Apache verifier that accepts every hostname." },
    { "Allow All Hostname Verifier", "NoopHostnameVerifier", "CRITICAL", "Verifier that performs no hostname validation." },
    { "Insecure SSL Socket Factory", "SSLCertificateSocketFactory.getInsecure(", "CRITICAL", "Returns a socket factory with no certificate validation." },
    { "Global Hostname Verifier Override", "HttpsURLConnection.setDefaultHostnameVerifier(", "HIGH", "Overrides hostname verification for every HTTPS connection in the app." },

    { "Weak Hash Algorithm", "MessageDigest.getInstance(\"SHA1\")", "HIGH", "SHA-1 (alias without hyphen) is deprecated for security-sensitive use." },
    { "Insecure SSLContext", "SSLContext.getInstance(\"SSLv3\")", "HIGH", "SSLv3 is broken (POODLE); use TLS 1.2+." },
    { "Trust Self-Signed Certificates", "TrustSelfSignedStrategy", "HIGH", "Apache HttpClient strategy that accepts self-signed certificates." },
    { "Insecure RSA Padding", "Cipher.getInstance(\"RSA/ECB/NoPadding\")", "HIGH", "Textbook RSA without padding is insecure and malleable." },
    { "Insecure RSA Padding", "Cipher.getInstance(\"RSA/ECB/PKCS1Padding\")", "MEDIUM", "PKCS#1 v1.5 padding is vulnerable to padding-oracle attacks; prefer OAEP." },
    { "Predictable Seed", "setSeed(System.currentTimeMillis()", "HIGH", "Seeding a RNG with the current time makes output predictable." },
    { "Global SSL Socket Factory Override", "HttpsURLConnection.setDefaultSSLSocketFactory(", "HIGH", "Replaces the SSL socket factory for every HTTPS connection in the app." },
};
 
masvs_pattern network_security_patterns[] =
{
 
    { "Cleartext HTTP URL", "http://", "MEDIUM", "Hardcoded cleartext HTTP URL detected; data transmitted is unencrypted." },
    { "WebSocket Insecure Scheme", "ws://", "MEDIUM", "Unencrypted WebSocket connection (ws://) detected instead of wss://." },
 
    { "OkHttp Body Logging", "HttpLoggingInterceptor.Level.BODY", "MEDIUM", "Full request/response body logging can leak tokens and personal data." },
    { "Emulator Localhost URL", "http://10.0.2.2", "MEDIUM", "Leftover development endpoint pointing at the Android emulator host." },
    { "Private Network URL", "http://192.168.", "MEDIUM", "Hardcoded internal network address; leaks infrastructure details." },
};
 
 
masvs_pattern platform_defenses[] =
{
 

    { "Xposed Framework Detection", "de.robv.android.xposed", "MEDIUM", "Checks for Xposed Framework, which can hook and modify app behavior." },
    { "Frida Detection", "frida-server", "MEDIUM", "Checks for Frida server process, a dynamic instrumentation toolkit." },
    { "Runtime Exec Root Check", "Runtime.getRuntime().exec(\"su\")", "MEDIUM", "Executes su via Runtime.exec to test root access." },
    { "Su Binary Check", "/system/bin/su", "MEDIUM", "Checks for su binary in /system/bin, the standard root indicator path." },
    { "Su Binary Check", "/system/xbin/su", "MEDIUM", "Checks for su binary in /system/xbin, a standard root indicator path." },
    { "Su Binary Check", "/sbin/su", "MEDIUM", "Checks for su binary in /sbin, common on rooted devices." },
 
  
    { "Application Debuggable Flag", "ApplicationInfo.FLAG_DEBUGGABLE", "MEDIUM", "Checks the application's debuggable flag at runtime." },
    { "Ptrace Anti-Debug", "ptrace(PTRACE_TRACEME", "MEDIUM", "Uses ptrace self-tracing to prevent a debugger from attaching." },
    { "TracerPid Check", "TracerPid", "MEDIUM", "Inspects /proc/self/status TracerPid field to detect debuggers." },
    { "Anti Frida Detection", "gum-js-loop", "MEDIUM", "Checks for Frida's internal thread name used during instrumentation." },
    { "Anti Frida Detection", "frida_agent", "MEDIUM", "Checks for Frida agent library presence." },
 
   
    { "APK Signature Hash Check", "signatures[0].hashCode()", "MEDIUM", "Compares signature hash to detect resigned/tampered APKs." },
    { "Hooking Framework Detection", "com.saurik.substrate", "MEDIUM", "Detects Cydia Substrate hooking framework." },
 
  
    { "Root Detection Library", "com.scottyab.rootbeer", "MEDIUM", "RootBeer root-detection library in use." },
    { "Play Integrity API", "com.google.android.play.core.integrity", "MEDIUM", "Play Integrity attestation in use; verify the verdict is checked server-side." },
    { "Debugger Detection", "Debug.isDebuggerConnected()", "MEDIUM", "Runtime check for an attached Java debugger." },
    { "Screenshot Protection", "FLAG_SECURE", "MEDIUM", "Window uses FLAG_SECURE to block screenshots and screen recording." },
};
 
masvs_pattern data_storages[] =
{
 
 
    { "World Readable Mode", "MODE_WORLD_READABLE", "CRITICAL", "Deprecated and insecure mode allowing any app to read preferences/files." },
    { "World Writable Mode", "MODE_WORLD_WRITABLE", "CRITICAL", "Deprecated and insecure mode allowing any app to modify preferences/files." },
    { "Storing Sensitive Data", "putString(\"password\"", "CRITICAL", "Potential storage of a password in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"token\"", "HIGH", "Potential storage of an auth token in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"api_key\"", "HIGH", "Potential storage of an API key in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"secret\"", "HIGH", "Potential storage of a secret value in plaintext SharedPreferences." },
 
   
    { "String Concatenation in Query", "\"SELECT * FROM \" +", "HIGH", "String concatenation in SQL queries is vulnerable to SQL injection." },
 
  
    { "External Storage Write", "getExternalStorageDirectory()", "HIGH", "Writing to external storage exposes data to any app with storage permission." },
    { "MANAGE_EXTERNAL_STORAGE Permission", "MANAGE_EXTERNAL_STORAGE", "HIGH", "Broad permission granting access to all files on external storage." },
    { "FileOutputStream to External Path", "FileOutputStream(\"/sdcard/", "HIGH", "Direct write to /sdcard path; verify no sensitive data is exposed." },
    { "World Readable File", "setReadable(true, false)", "HIGH", "Makes a file readable by every app on the device." },
    { "Public External Storage", "getExternalStoragePublicDirectory(", "HIGH", "Writes to shared public storage readable by other apps." },
 

    { "Storing Sensitive Data", "putString(\"pin\"", "CRITICAL", "Potential storage of a PIN in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"access_token\"", "HIGH", "Potential storage of an access token in plaintext SharedPreferences." },
    { "Storing Sensitive Data", "putString(\"refresh_token\"", "HIGH", "Potential storage of a refresh token in plaintext SharedPreferences." },
    { "SQL Injection Risk", "= '\" +", "HIGH", "Quoted SQL value followed by string concatenation is vulnerable to injection." },
    { "SQL Injection Risk", "LIKE '%\" +", "HIGH", "LIKE clause built with string concatenation is vulnerable to injection." },
};
 
masvs_pattern code_executions[] =
{

    { "DexClassLoader Usage", "DexClassLoader(", "HIGH", "Dynamically loads external DEX code, a common malware/evasion technique." },
    { "DexFile Loading", "DexFile.loadDex(", "HIGH", "Explicit dynamic loading of DEX files at runtime." },
    { "Native Library Dynamic Load", "System.load(", "MEDIUM", "Loads a native library from an absolute path at runtime." },
 
    { "Reflection on System Classes", "Class.forName(\"android.os", "HIGH", "Reflective access to internal Android OS classes, often used to bypass restrictions." },
 
    { "Runtime Exec Call", "Runtime.getRuntime().exec(", "HIGH", "Executes an OS-level command; verify inputs are not user-controlled." },
    { "ProcessBuilder Usage", "ProcessBuilder(", "HIGH", "Spawns a new OS process; verify command arguments are sanitized." },
    { "Shell Command Execution", "/system/bin/sh", "HIGH", "Directly invokes a shell, high risk of command injection if input is unsanitized." },
    { "Mutable PendingIntent", "PendingIntent.FLAG_MUTABLE", "MEDIUM", "Mutable PendingIntents can be hijacked and redirected by other apps." },
 
   
    { "Intent Redirection", "Intent.parseUri(", "HIGH", "Builds an Intent from an untrusted URI string; risk of intent redirection." },
    { "Sticky Broadcast", "sendStickyBroadcast(", "MEDIUM", "Sticky broadcasts are deprecated and readable by any app." },
    { "Unsafe Memory Access", "sun.misc.Unsafe", "MEDIUM", "Direct memory access via sun.misc.Unsafe bypasses JVM safety." },
    { "Chmod Command Execution", "exec(\"chmod", "HIGH", "Changes file permissions via shell; may create world-accessible files." },
};
 
masvs_pattern web_natives[] = 
{
 
   
    { "JavaScript Interface Exposure", "addJavascriptInterface(", "HIGH", "Exposes Java objects to JavaScript, risk of remote code execution pre-API 17." },
    { "Universal File Access", "setAllowUniversalAccessFromFileURLs(true)", "CRITICAL", "Allows universal access from file URLs, a severe security risk." },
    { "File Access From File URLs", "setAllowFileAccessFromFileURLs(true)", "HIGH", "Allows file-scheme pages to access other file-scheme resources." },
    { "Mixed Content Allowed", "setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW)", "HIGH", "Allows insecure HTTP content to load within an HTTPS WebView page." },
    { "WebView Debugging Enabled", "setWebContentsDebuggingEnabled(true)", "MEDIUM", "Enables remote WebView debugging, should be disabled in production." },
    { "Ignore SSL Errors", "handler.proceed()", "CRITICAL", "Proceeds despite SSL errors, bypassing certificate validation in WebView." },
    { "Load URL From Intent", "loadUrl(getIntent()", "HIGH", "Loads a URL sourced from an external Intent, potential injection vector." },
    { "Safe Browsing Disabled", "setSafeBrowsingEnabled(false)", "MEDIUM", "Disables Google Safe Browsing protection in WebView." },
 
 
    { "Native Library From External Storage", "loadLibrary(\"/sdcard/", "CRITICAL", "Loads a native library from external storage, a severe code injection risk." },
 
  
    { "JavaScript URL Injection", "loadUrl(\"javascript:", "MEDIUM", "Executes JavaScript via loadUrl; verify no untrusted data is concatenated." },
    { "WebView Loads External Storage", "loadUrl(\"file:///sdcard", "HIGH", "Loads content from external storage that other apps can modify." },
    { "Load URL From Intent Extra", "loadUrl(getIntent().getStringExtra(", "HIGH", "Loads a URL taken from an Intent extra; open redirect / injection vector." },
    { "WebView Save Password", "setSavePassword(true)", "HIGH", "WebView stores passwords in plaintext (deprecated and insecure)." },
    { "JavaScript Interface Method", "@JavascriptInterface", "MEDIUM", "Method exposed to JavaScript; verify the WebView only loads trusted content." },
    { "Intent URI Scheme", "Intent.URI_INTENT_SCHEME", "MEDIUM", "Parses intent: URIs from web content; risk of intent redirection." },
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
    "http://schemas.android.com/apk/res-auto"
};

int pattern_count = sizeof(patterns) / sizeof(patterns[0]);
int permission_count = sizeof(permission) / sizeof(permission[0]);
int manifest_count = sizeof(manifest_scan) / sizeof(manifest_scan[0]);
int strings_count = sizeof(string_patterns) / sizeof(string_patterns[0]);

int weak_network = sizeof(weak_networks) / sizeof(weak_networks[0]);
int platform_defense = sizeof(platform_defenses) / sizeof(platform_defenses[0]);
int data_storage = sizeof(data_storages) / sizeof(data_storages[0]);
int code_execution = sizeof(code_executions) / sizeof(code_executions[0]);
int web_native = sizeof(web_natives) / sizeof(web_natives[0]);
int masvs_network_security_patterns_count = sizeof(network_security_patterns) / sizeof(network_security_patterns[0]);
int false_positives_count = sizeof(false_positives) / sizeof(false_positives[0]);

int count_patterns = sizeof(Bucket) / sizeof(Bucket[0]);
int count_secrets = sizeof(secrets) / sizeof(secrets[0]);


regex_t bucket_regexes[sizeof(Bucket) / sizeof(Bucket[0])];
regex_t secret_regexes[sizeof(secrets) / sizeof(secrets[0])];


