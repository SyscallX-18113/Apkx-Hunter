/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef EXTRACT_H
#define EXTRACT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <limits.h>
#include <sys/types.h>
#include "multi_apk.h"
#include "define.h"


int folder(const char *path);
void count_apks(const char *folder);
int extract_apk(char *argv[], char *output_dir);
int extract_apk_1(int argc, char *argv[], char *output_dir);


#endif