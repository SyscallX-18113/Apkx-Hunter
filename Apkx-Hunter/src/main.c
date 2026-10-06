/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <sys/types.h>
#include <stddef.h>
#include "define.h"
#include "banner.h"
#include "patterns.h"
#include "functions.h"
#include "jadx.h"
#include "scan_secrets.h"
#include "apktool.h"
#include "extract.h"
#include "multi_apk.h"
#include "masvs.h"
#include "ah_shell_interface.h"

#define MODEL_PATH "/usr/share/apkx-hunter/model.bin"
#define MODEL_PATH_1 "model/model.bin"



int main()
{
    printf(HACKER_WHITE);

    animation();
    sleep(2);
    
    if (access(MODEL_PATH, F_OK) != 0 &&
        access(MODEL_PATH_1, F_OK) != 0)
    {
        printf(HACKER_WHITE);

        printf("\n[ERROR] AI model not found!\n");
        printf("Expected location:\n");
        printf("%s\n", MODEL_PATH);
        printf("Or the current working directory.\n");
        printf("Secret Detection cannot run without model.bin.\n\n");

        printf(COLOR_RESET);

        return 1;
    }


    print_banner();

    command_line();

    printf(COLOR_RESET);
    

    return 0;
}
