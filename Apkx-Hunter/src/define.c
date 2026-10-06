/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "define.h"

const char *valid_flags[] =
    {
        INSTALL,
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
        HELP,
        RUN,
        EXIT,
        BANNER,
        SEARCH,
        QUIET
    };


int silent_mode = 1;
int deep_2 = 0;
int exit_2 = 0;
int run_2 = 0;
int banner_2 = 0;
int search_2 = 0;
int quiet_2 = 0;
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
int install = 0;
int not_valid_apk = 0;
int apk_count = 0;

void reset_command_state(void)
{
    silent_mode = 1;
    deep_2 = fast_2 = search_2 = banner_2 = quiet_2 = run_2 = exit_2 = 0;
    extract_multi_apk_2 = secrets_2 = folder_scan_2 = permissions_2 = 0;
    patterns_2 = decompile_2 = file_scan_2 = apktool_2 = apktool_scan_2 = 0;
    multi_apk_2 = extract_2 = masvs_2 = install = help_2 = 0;
    not_valid_apk = 0;
    apk_count = 0;
    memset(&stats, 0, sizeof(stats));
}

ScanStats stats = {0};

int valid_flag_count = sizeof(valid_flags) / sizeof(valid_flags[0]);
