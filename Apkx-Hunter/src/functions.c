/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */


 #include "functions.h"
 #include "patterns.h"



int statics()
{
    printf(HACKER_WHITE);
    printf("\n===================================================\n");
    printf("                  Statistics\n");
    printf("=====================================================\n\n");
    printf("APK(s) Scanned                               : %d\n", stats.apks_scanned);
    printf("Files Analyzed                               : %d\n", stats.files_analyzed);
    printf("\n===================================================\n\n");
    printf("Secrets Patterns Detected                    : %d\n", stats.secrets);
    printf("Patterns Detected                            : %d\n", stats.patterns);
    printf("MASVS Findings                               : %d\n", stats.masvs);
    printf("Permissions And Exported Activity Findings   : %d\n", stats.permissions);
    printf("=====================================================\n\n");
    printf(COLOR_RESET);
    return 0;
}

int statics_1()
{
    printf(HACKER_WHITE);
    printf("\n=====================================================\n");
    printf("                  Statistics\n");
    printf("=====================================================\n\n");
    printf("APK(s) Scanned                               : %d\n", stats.apks_scanned);
    printf("=====================================================\n\n");
    printf(COLOR_RESET);
    return 0;
}

void scan_buckets(const char *filepath, FILE *for_regex, char *line, int bucket_count, int line_no)
{

    for (int i = 0; i < bucket_count; i++)
    {
        printf(ORANGE);
        regmatch_t match[2];

        if (regexec(&bucket_regexes[i],
                    line,
                    2,
                    match,
                    0) == 0)
        {
            char found[512];

            int len = match[0].rm_eo - match[0].rm_so;

            if ((size_t)len >= sizeof(found))
            {
                len = sizeof(found) - 1;
            }

            strncpy(found,
                    line + match[0].rm_so,
                    (size_t)len);

            found[len] = '\0';

            printf("FOUND: %s\n",
                   Bucket[i].name);

            if (match[1].rm_so != -1)
            {
                if (silent_mode == 1)
                {
                    printf("FOUND: %s \nFile: %s:%d\n",
                           found, filepath, line_no);
                    printf("\n");
                }

                fprintf(for_regex,
                        "[Cloud_Bucket] %s:%d -> %s\n \t %s \n\n",
                        filepath,
                        line_no,
                        Bucket[i].name, found);
                stats.secrets++;
            }
            else

            {
                if (silent_mode == 1)
                {
                    printf("FOUND: %s \nFile: %s:%d\n",
                           found, filepath, line_no);
                    printf("\n");
                }
                fprintf(for_regex,
                        "[Cloud_Bucket] %s:%d -> %s\n \t %s\n\n",
                        filepath,
                        line_no,
                        Bucket[i].name, found);
                stats.secrets++;
            }
        }
        printf(COLOR_RESET);
    }
}

void scan_patterns(const char *filepath, FILE *for_patterns, char *line, int line_no)
{

    for (int i = 0; i < pattern_count; i++)
    {
        if (strstr(line, patterns[i]))
        {
            fprintf(for_patterns,
                    "%s:%d -> %s\n Line: %s\n",
                    filepath,
                    line_no,
                    patterns[i], line);
            stats.patterns++;

            if (silent_mode == 1)
            {
                printf("[ENDPOINT_Found] %s:%d -> %s\n Line: %s\n", filepath, line_no, patterns[i], line);
            }
        }
    }
}

void scan_permissions(const char *filepath, FILE *for_permissions, char *line, int line_no)
{

    for (int i = 0; i < permission_count; i++)
    {
        if (strstr(line, permission[i].permission))
        {
            fprintf(for_permissions,
                    "%s:%d -> %s\nDefinition: %s\n\n",
                    filepath,
                    line_no,
                    permission[i].permission,
                    permission[i].definition);
            stats.permissions++;

            if (silent_mode == 1)
            {
                printf("[PERMISSION_FOUND]\n");
                printf("File: %s:%d\n",
                       filepath,
                       line_no);

                printf("Permission: %s\n",
                       permission[i].permission);

                printf("Definition: %s\n\n",
                       permission[i].definition);
            }
        }
    }
}

void scan_exported_activity(const char *filepath, FILE *for_permissions, char *line, int line_no)
{

    printf(ORANGE);
    if (strstr(filepath, ".xml"))
    {
        for (int i = 0; i < manifest_count; i++)
        {

            if (strstr(line, manifest_scan[i].pattern))
            {
                fprintf(for_permissions,
                        "[MANIFEST_SCAN_Result]\nFilepath %s:%d -> %s\nFound: %s\n", filepath, line_no, manifest_scan[i].name, line);
                stats.permissions++;

                if (silent_mode == 1)
                {
                    printf("[MANIFEST_SCAN_Result]\nFilepath %s:%d -> %s\nFound: %s\n", filepath, line_no, manifest_scan[i].name, line);
                }
            }
        }
    }
    printf(COLOR_RESET);
}

void scan_native_libraries(const char *filepath, FILE *for_native_lib)
{

    if (strstr(filepath, ".so"))
    {

        fprintf(for_native_lib,
                "Filepath: %s\n", filepath);
    }
}

void print_files(const char *filepath, FILE *scan_files)
{

    fprintf(scan_files,
            "%s\n",
            filepath);
}

void scan_strings_xml(const char *filepath, FILE *for_regex, char *line, int line_no)
{
    printf(LIGHT_RED);
    if (strstr(filepath, ".xml"))
    {
        for (int i = 0; i < strings_count; i++)
        {
            if (strstr(line, string_patterns[i].pattern))
            {
                fprintf(for_regex, "[Strings Found Result]\nFilePath %s:%d -> %s\n FOUND: %s\n", filepath, line_no, string_patterns[i].name, line);
                stats.secrets++;

                if (silent_mode == 1)
                {
                    printf("[Strings Found Result]\nFilePath %s:%d -> %s\n FOUND: %s\n", filepath, line_no, string_patterns[i].name, line);
                }
            }
        }
    }
    printf(COLOR_RESET);
}

void cleanup_bucket_regexes(void)
{
    
    for (int i = 0; i < count_patterns; i++)
    {
        regfree(&bucket_regexes[i]);
    }


    for (int n = 0; n < count_secrets; n++)
    {
        regfree(&secret_regexes[n]);
    }
}

int init_bucket_regexes(void)
{
    printf(HACKER_WHITE);

    

    for (int i = 0; i < count_patterns; i++)
    {
        int ret = regcomp(&bucket_regexes[i],
                          Bucket[i].pattern,
                          REG_EXTENDED | REG_ICASE);

        if (ret != 0)
        {
            printf("FAILED TO COMPILE: %s\n", Bucket[i].name);
            return 1;
        }
    }

    for (int n = 0; n < count_secrets; n++)
    {
        int ret = regcomp(&secret_regexes[n],
                          secrets[n].pattern,
                          REG_EXTENDED | REG_ICASE);

        if (ret != 0)
        {
            printf("FAILED TO COMPILE: %s\n",
                   secrets[n].name);
            return 1;
        }
    }
    printf(COLOR_RESET);
}

int is_apk(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        return 0;

    unsigned char header[4];
    fread(header, 1, 4, f);
    fclose(f);

    if (header[0] == 'P' && header[1] == 'K')
        return 1;

    return 0;
}

int check_apk(char *apk_path)
{

    if (!is_apk(apk_path))
    {
        printf(HACKER_WHITE "Not a valid APK file: %s\n" COLOR_RESET, apk_path);
        not_valid_apk++;
        return 1;
    }
    FILE *apk = fopen(apk_path, "rb");

    if (apk == NULL)
    {
        printf(HACKER_WHITE "APK not found: %s\n" COLOR_RESET, apk_path);
        not_valid_apk++;
        return 1;
    }

    printf(HACKER_WHITE "\n\n\nAPK found: %s\n" COLOR_RESET, apk_path);

    fseek(apk, 0, SEEK_END);
    long size_bytes = ftell(apk);
    fclose(apk);

    double size_mb = (double)size_bytes / (1024 * 1024);

    printf(HACKER_WHITE "APK Size: %.2f MB\n\n" COLOR_RESET, size_mb);
    return 1;
}

int compute_hashes(const char *filepath)
{
    if (not_valid_apk == 0)
    {

        FILE *file = fopen(filepath, "rb");
        if (!file)
        {
            perror("Error opening file");
            return 1;
        }

        unsigned char md5_digest[MD5_DIGEST_LENGTH];
        unsigned char sha1_digest[SHA_DIGEST_LENGTH];
        unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
        unsigned char buffer[8192];
        size_t bytes;
        MD5_CTX md5_ctx;
        SHA_CTX sha1_ctx;
        SHA256_CTX sha256_ctx;

        MD5_Init(&md5_ctx);
        SHA1_Init(&sha1_ctx);
        SHA256_Init(&sha256_ctx);

        while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
        {
            MD5_Update(&md5_ctx, buffer, bytes);
            SHA1_Update(&sha1_ctx, buffer, bytes);
            SHA256_Update(&sha256_ctx, buffer, bytes);
        }

        MD5_Final(md5_digest, &md5_ctx);
        SHA1_Final(sha1_digest, &sha1_ctx);
        SHA256_Final(sha256_digest, &sha256_ctx);

        fclose(file);
        printf(HACKER_WHITE);

        printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        printf("APK HASHES\n");

        printf("MD5:    ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
            printf("%02x", md5_digest[i]);
        printf("\n");

        printf("SHA-1:  ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            printf("%02x", sha1_digest[i]);
        printf("\n");

        printf("SHA-256:");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            printf("%02x", sha256_digest[i]);
        printf("\n");
        printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        printf(COLOR_RESET);
    }
    else
    {
        return 1;
    }
}

void install_missing_dependencies(void) {
    char cmd[1024];
    int has_sudo = (geteuid() != 0);
 
    
    if (system("command -v unzip >/dev/null 2>&1") != 0) {
        printf(HACKER_WHITE "[*] Installing unzip..." COLOR_RESET "\n");
        snprintf(cmd, sizeof(cmd), "%sapt-get update -qq && %sapt-get install -y -qq unzip",
                 has_sudo ? "sudo " : "", has_sudo ? "sudo " : "");
        if (system(cmd) != 0 || system("command -v unzip >/dev/null 2>&1") != 0) 
        {
            fprintf(stderr, LIGHT_RED "[FAIL] unzip installation failed. Check network/sudo access and try manually: apt-get install unzip" COLOR_RESET "\n");
        } 
        
        else 
        {
            printf(GREEN "[OK] unzip installed" COLOR_RESET "\n");
        }
    } 
    
    else
    {
        printf(GREEN "[OK] unzip found" COLOR_RESET "\n");
    }
 
    
    if (system("command -v jadx >/dev/null 2>&1") != 0) 
    {
        printf(HACKER_WHITE "[*] Installing JADX..." COLOR_RESET "\n");
        snprintf(cmd, sizeof(cmd),
            "URL=$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest "
            "| grep -o '\"browser_download_url\": *\"[^\"]*jadx-[0-9][^\"]*\\.zip\"' "
            "| head -n1 | cut -d'\"' -f4); "
            "[ -n \"$URL\" ] || exit 1; "
            "curl -fsSL -o /tmp/jadx.zip \"$URL\" || exit 2; "
            "%smkdir -p /opt/jadx && %sunzip -oq /tmp/jadx.zip -d /opt/jadx || exit 3; "
            "%schmod +x /opt/jadx/bin/jadx && %sln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx",
            has_sudo ? "sudo " : "", has_sudo ? "sudo " : "",
            has_sudo ? "sudo " : "", has_sudo ? "sudo " : "");
 
        int rc = system(cmd);
        if (rc != 0) {
            int code = rc / 256;
            if (code == 1)      fprintf(stderr, LIGHT_RED "[FAIL] JADX install failed: could not find a matching release asset on GitHub." COLOR_RESET "\n");
            else if (code == 2) fprintf(stderr, LIGHT_RED "[FAIL] JADX install failed: download from GitHub failed (check internet connection)." COLOR_RESET "\n");
            else if (code == 3) fprintf(stderr, LIGHT_RED "[FAIL] JADX install failed: could not extract the archive (unzip missing or corrupt zip)." COLOR_RESET "\n");
            else                fprintf(stderr, LIGHT_RED "[FAIL] JADX install failed for an unknown reason." COLOR_RESET "\n");
        } 
        
        else if (system("command -v jadx >/dev/null 2>&1") != 0) 
        {
            fprintf(stderr, LIGHT_RED "[FAIL] JADX install ran but 'jadx' command still not found in PATH." COLOR_RESET "\n");
        } 
        
        else 
        {
            printf(GREEN "[OK] JADX installed" COLOR_RESET "\n");
        }
    } 
    
    else 
    {
        printf(GREEN "[OK] JADX found" COLOR_RESET "\n");
    }
 
    
    if (system("command -v apktool >/dev/null 2>&1") != 0) 
    {
        printf(HACKER_WHITE "[*] Installing APKTool..." COLOR_RESET "\n");
        snprintf(cmd, sizeof(cmd), "URL=$(curl -fsSL https://api.github.com/repos/iBotPeaches/Apktool/releases/latest "
            "| grep -o '\"browser_download_url\": *\"[^\"]*apktool_[0-9][^\"]*\\.jar\"' "
            "| head -n1 | cut -d'\"' -f4); "
            "[ -n \"$URL\" ] || exit 1; "
            "curl -fsSL -o /tmp/apktool.jar \"$URL\" || exit 2; "
            "curl -fsSL -o /tmp/apktool https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool || exit 2; "
            "%sinstall -m 755 /tmp/apktool /usr/local/bin/apktool || exit 3; "
            "%sinstall -m 644 /tmp/apktool.jar /usr/local/bin/apktool.jar || exit 3",
            has_sudo ? "sudo " : "", has_sudo ? "sudo " : "");
 
        int rc = system(cmd);
        if (rc != 0) 
        {
            int code = rc / 256;
            if (code == 1)      fprintf(stderr, LIGHT_RED "[FAIL] APKTool install failed: could not find a matching release asset on GitHub." COLOR_RESET "\n");
            else if (code == 2) fprintf(stderr, LIGHT_RED "[FAIL] APKTool install failed: download failed (check internet connection)." COLOR_RESET "\n");
            else if (code == 3) fprintf(stderr, LIGHT_RED "[FAIL] APKTool install failed: could not copy files to /usr/local/bin (check sudo access)." COLOR_RESET "\n");
            else                fprintf(stderr, LIGHT_RED "[FAIL] APKTool install failed for an unknown reason." COLOR_RESET "\n");
        }
        
        else if (system("command -v apktool >/dev/null 2>&1") != 0) 
        {
            fprintf(stderr, LIGHT_RED "[FAIL] APKTool install ran but 'apktool' command still not found in PATH." COLOR_RESET "\n");
        } 
        
        else 
        {
            printf(GREEN "[OK] APKTool installed" COLOR_RESET "\n");
        }
    } 
    
    else 
    {
        printf(GREEN "[OK] APKTool found" COLOR_RESET "\n");
    }
}

