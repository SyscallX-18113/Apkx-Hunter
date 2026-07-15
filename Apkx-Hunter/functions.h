#ifndef FUNCTIONS_H
#define FUNCTIONS_H
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

void scan_buckets(const char *filepath, FILE *for_regex, char *line, int bucket_count, int line_no);
void scan_patterns(const char *filepath, FILE *for_patterns, char *line, int line_no);
void scan_permissions(const char *filepath, FILE *for_permissions, char *line, int line_no);
void cleanup_bucket_regexes(void);
void init_bucket_regexes(void);
void scan_exported_activity(const char *filepath, FILE *for_permissions, char *line, int line_no);
void print_files(const char *filepath, FILE *scan_files);
void scan_strings_xml(const char *filepath, FILE *for_permissions, char *line, int line_no);
void scan_native_libraries(const char *filepath, FILE *for_native_lib);

int pattern_count = sizeof(patterns) / sizeof(patterns[0]);
int permission_count = sizeof(permission) / sizeof(permission[0]);
int manifest_count = sizeof(manifest_scan) / sizeof(manifest_scan[0]);
int strings_count = sizeof(string_patterns) / sizeof(string_patterns[0]);



regex_t bucket_regexes[sizeof(Bucket) / sizeof(Bucket[0])];
regex_t secret_regexes[sizeof(secrets) / sizeof(secrets[0])];

#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "file_making.h"
#include "scan_dir_func.h"
#include "scan_secrets.h"

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
                printf("FOUND: %s \nFile: %s:%d\n",
                       found, filepath, line_no);
                printf("\n");

                fprintf(for_regex,
                        "[Cloud_Bucket] %s:%d -> %s\n \t %s \n\n",
                        filepath,
                        line_no,
                        Bucket[i].name, found);
            }
            else

            {
                printf("FOUND: %s \nFile: %s:%d\n",
                       found, filepath, line_no);
                printf("\n");
                fprintf(for_regex,
                        "[Cloud_Bucket] %s:%d -> %s\n \t %s\n\n",
                        filepath,
                        line_no,
                        Bucket[i].name, found);
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

            printf("[ENDPOINT_Found] %s:%d -> %s\n Line: %s\n", filepath, line_no, patterns[i], line);
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

                printf("[MANIFEST_SCAN_Result]\nFilepath %s:%d -> %s\nFound: %s\n", filepath, line_no, manifest_scan[i].name, line);
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
                fprintf(for_regex,
                        "[Strings Found Result]\nFilePath %s:%d -> %s\n FOUND: %s\n", filepath, line_no, string_patterns[i].name, line);

                printf("[Strings Found Result]\nFilePath %s:%d -> %s\n FOUND: %s\n", filepath, line_no, string_patterns[i].name, line);
            }
        }
    }
    printf(COLOR_RESET);
}




void cleanup_bucket_regexes(void)
{
    int count_patterns =
        sizeof(Bucket) /
        sizeof(Bucket[0]);

    for (int i = 0; i < count_patterns; i++)
    {
        regfree(&bucket_regexes[i]);
    }

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    for (int n = 0; n < count_secrets; n++)
    {
        regfree(&secret_regexes[n]);
    }
}

void init_bucket_regexes(void)
{
    printf(HACKER_WHITE);

    int count =
        sizeof(Bucket) /
        sizeof(Bucket[0]);

    for (int i = 0; i < count; i++)
    {
        int ret = regcomp(&bucket_regexes[i],
                          Bucket[i].pattern,
                          REG_EXTENDED | REG_ICASE);

        if (ret != 0)
        {
            printf("FAILED TO COMPILE: %s\n", Bucket[i].name);
        }
    }

    int count_secrets = sizeof(secrets) / sizeof(secrets[0]);

    for (int n = 0; n < count_secrets; n++)
    {
        int ret = regcomp(&secret_regexes[n],
                          secrets[n].pattern,
                          REG_EXTENDED | REG_ICASE);

        if (ret != 0)
        {
            printf("FAILED TO COMPILE: %s\n",
                   secrets[n].name);
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

    // APK = ZIP signature
    if (header[0] == 'P' && header[1] == 'K')
        return 1;

    return 0;
}

int check_apk(char *apk_path)
{

    if (!is_apk(apk_path))
    {
        printf(HACKER_WHITE "Not a valid APK file: %s\n"COLOR_RESET, apk_path);
        return 0;
    }
    FILE *apk = fopen(apk_path, "rb");

    if (apk == NULL)
    {
        printf(HACKER_WHITE "APK not found: %s\n"COLOR_RESET, apk_path);
        return 0;
    }

    printf(HACKER_WHITE "APK found: %s\n"COLOR_RESET, apk_path);

    fseek(apk, 0, SEEK_END);
    long size_bytes = ftell(apk);
    fclose(apk);

    double size_mb = (double)size_bytes / (1024 * 1024);

    printf(HACKER_WHITE "APK Size: %.2f MB\n\n"COLOR_RESET, size_mb);
    return 1;
}

void compute_hashes(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("Error opening file");
        return;
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

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
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

#endif
