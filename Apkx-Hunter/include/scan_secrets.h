/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef SCAN_SECRETS_H
#define SCAN_SECRETS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <regex.h>

int scan_secrets(const char *filepath,
                 FILE *for_regex,
                 char *line,
                 int count_secrets,
                 int line_no);


#include "patterns.h"
#include "define.h"
#include "main_ai.h"
#include "file_making.h"
#include "scan_dir_func.h"


#endif 