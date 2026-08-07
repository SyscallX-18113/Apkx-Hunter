/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef APKTOOL_H
#define APKTOOL_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "define.h"
#include "file_making.h"
#include "functions.h"
#include "jadx.h"

int run_apktool(char *argv[], char *output_dir, int argc);
int run_apktool_1(char *argv[], char *full_path, char *output_dir, int argc);

#endif
