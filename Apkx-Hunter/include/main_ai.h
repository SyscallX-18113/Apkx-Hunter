/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef MAIN_AI_H
#define MAIN_AI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include "run.h"
#include "define.h"

void classify_and_print(const Model *m, const char *value, const char *filepath,
                               FILE *for_regex,
                               int line_no, int n);
int ai_model(const char *filepath,
             FILE *for_regex,
             int line_no, const char *value, int n);

#endif