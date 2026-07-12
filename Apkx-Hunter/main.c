#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <stddef.h>
#include "banner.h"
#include "patterns.h"
#include "functions.h"
#include "define.h"
#include "jadx.h"
#include "scan_secrets.h"
#include "apktool.h"
#include "extract.h"

int main(int argc, char *argv[])
{

    if (argc >= 3 &&
        (argv[2] != NULL &&
         strcmp(argv[2], FAST) != 0 &&
         strcmp(argv[2], DEEP) != 0 &&
         strcmp(argv[2], FOLDER_SCAN) != 0 &&
         strcmp(argv[2], APKTOOL) != 0 &&
         strcmp(argv[2], DECOMPILE) != 0 &&
         strcmp(argv[2], APKTOOL_SCAN) != 0 &&
         strcmp(argv[2], EXTRACT) != 0))
    {
        printf(HACKER_WHITE "Error: Unknown option '%s'\n"COLOR_RESET, argv[2]);
        printf(HACKER_WHITE "Use -h to see available options.\n"COLOR_RESET);
        return 1;
    }

    if (argc >= 4 &&
        (argv[3] != NULL &&
         strcmp(argv[3], SECRETS) != 0 &&
         strcmp(argv[3], PERMISSIONS) != 0 &&
         strcmp(argv[3], PATTERNS) != 0 &&
         strcmp(argv[3], DECOMPILE) != 0 &&
         strcmp(argv[3], FILE_SCAN) != 0))
    {
        printf(HACKER_WHITE "Error: Unknown option '%s'\n"COLOR_RESET, argv[3]);
        printf(HACKER_WHITE "Use -h to see available options.\n"COLOR_RESET);
        return 1;
    }

    init_bucket_regexes();
    print_banner();

    if (argc == 1)
    {
        printf(HACKER_WHITE "Usage: %s <apk|folder> --deep | --fast | --folder-scan OR %s -h \n"COLOR_RESET, argv[0], argv[0]);
        return 1;
    }

    // HELP MODE
    if (strcmp(argv[1], HELP) == 0)
    {
        help_func();
        return 0;
    }

    if (argc >= 3 && (strcmp(argv[2], EXTRACT) == 0) && (strstr(argv[1], ".apkm") != NULL || strstr(argv[1], ".aab") != NULL || strstr(argv[1], ".xapk") != NULL || strstr(argv[1], ".apks") != NULL))
    {
        char output_dir[256];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");

        if (dot)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "extracted_output_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }
        extract_apk(argv, output_dir);
        return 0;
    }

    // FOLDER SCAN MODE (IMPORTANT: NO APK LOGIC HERE)
    if ((strstr(argv[1], ".apk") == NULL) && (argc >= 3 && strcmp(argv[2], FOLDER_SCAN) == 0 || strcmp(argv[2], SECRETS) == 0 || strcmp(argv[2], PERMISSIONS) == 0 || strcmp(argv[2], PATTERNS) == 0))
    {
        file_making(argv[1], argv, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if ((strstr(argv[1], ".apk") == NULL) && (argc >= 3 && strcmp(argv[2], APKTOOL_SCAN) == 0))
    {
        file_making_for_apktool(argv[1], argv, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    if ((strstr(argv[1], ".apk") != NULL) && (argc >= 3 && strcmp(argv[2], APKTOOL) == 0))
    {

        
        char output_dir[256];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");

        if (dot)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "Apktool_output_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }
        run_apktool(argv, output_dir, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    // APK MODE
    if (strstr(argv[1], ".apk") != NULL)
    {
        char output_dir[256];

        char *apk_name = argv[1];
        char *dot = strstr(apk_name, ".apk");

        if (dot)
        {
            ptrdiff_t len = dot - apk_name;
            snprintf(output_dir, sizeof(output_dir),
                     "Jadx_output_%.*s", (int)len, apk_name);
        }
        else
        {
            snprintf(output_dir, sizeof(output_dir),
                     "output_default");
        }

        run_jadx(argv, output_dir, argc);
        cleanup_bucket_regexes();
        return 0;
    }

    printf("Invalid input\n");
    cleanup_bucket_regexes();
    return 0;
}
