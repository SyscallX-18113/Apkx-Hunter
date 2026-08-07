/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef MASVS_H
#define MASVS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>



#include "scan_secrets.h"
#include "patterns.h"
#include "define.h"
#include "file_making.h"


void scan_masvs_1(const char *filepath, FILE *for_masvs, char *line, int line_no);
void scan_masvs(const char *filepath, FILE *for_masvs, char *line, int line_no);


#endif