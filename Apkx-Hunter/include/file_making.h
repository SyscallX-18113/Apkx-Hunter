/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef FILE_MAKING_H
#define FILE_MAKING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>
#include <errno.h>
#include <sys/types.h>
#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "functions.h"
#include "scan_dir_func.h"

int file_making(char *output_dir, char *argv[], int argc);
int file_making_for_apktool(char *output_dir, char *argv[], int argc);


#endif
