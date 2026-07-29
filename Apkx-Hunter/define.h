/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef DEFINE_H
#define DEFINE_H


//COLORS
#define COLOR_MAGENTA         "\033[1;35m"
#define COLOR_RESET           "\033[0m"
#define GREEN                 "\033[32m"
#define COLOR_RED             "\033[1;31m"
#define COLOR_BLUE            "\033[1;34m"
#define _G                    "\033[38;5;46m"
#define LIGHT_BLUE            "\033[96m"
#define LIGHT_GREEN           "\033[92m"
#define LIGHT_BLUE_SECOND     "\033[94m"
#define LIGHT_MAGENTA         "\033[95m"
#define LIGHT_CYAN            "\033[96m"
#define LIGHT_WHITE           "\033[97m"
#define LIGHT_YELLOW          "\033[93m"

#define LIGHT_RED             "\033[91m"
#define ORANGE                "\033[38;2;255;165;0m"
#define HACKER_WHITE          "\033[97m"

//Other Defines

#define MAX_LINE 2048


//Flags

#define DEEP "--deep"
#define FAST "--fast"
#define SECRETS "--secrets"
#define HELP "--help"
#define FOLDER_SCAN "--folder-scan"
#define PERMISSIONS "--permissions"
#define PATTERNS "--endpoints"
#define DECOMPILE "--decompile"
#define FILE_SCAN "--files"
#define APKTOOL "--apktool"
#define APKTOOL_SCAN "--apktool-folder-scan"
#define MULTI_APK "--multi-apk"
#define EXTRACT "--extract"
#define MASVS "--masvs"
#define EXTRACT_MULTI_APK "--extract-multi-apk"

int silent_mode = 1;
int deep_2 = 0;
int fast_2 = 0;
int secrets_2 = 0;
int help_2 = 0;
int folder_scan_2 = 0;
int permissions_2 = 0;
int patterns_2 = 0;
int decompile_2 = 0;
int file_scan_2 = 0;
int apktool_2 = 0;
int apktool_scan_2 = 0;
int multi_apk_2 = 0;
int extract_2 = 0;
int masvs_2 = 0;
int extract_multi_apk_2 = 0;

int not_valid_apk = 0;
int apk_count = 0;

const char *valid_flags[] =
{
    
    FAST,
    DEEP,
    EXTRACT_MULTI_APK,
    FOLDER_SCAN,
    APKTOOL,
    MULTI_APK,
    DECOMPILE,
    APKTOOL_SCAN,
    EXTRACT,
    SECRETS,
    MASVS,
    PERMISSIONS,
    PATTERNS,
    FILE_SCAN,
    HELP
};

typedef struct
{
    int apks_scanned;
    int duplicate_apks_skipped;
    int files_analyzed;
    int secrets;
    int patterns;
    int masvs;
    int permissions;
} ScanStats;

ScanStats stats = {0};



#endif
