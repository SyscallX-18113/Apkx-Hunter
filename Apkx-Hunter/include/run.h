/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#ifndef RUN_H
#define RUN_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#define NUM_BASE_FEATURES 9
#define PREFIX_LEN 4
#define VOCAB_SIZE 40
#define NUM_FEATURES (NUM_BASE_FEATURES + VOCAB_SIZE)

#define MODEL_MAGIC 0x53454352


double squash(double x, double k);
void base_features_extract(const char *s, double out[NUM_BASE_FEATURES]); 
double sigmoid(double z);

typedef struct {
    char prefix[PREFIX_LEN + 1];
    double score;
} VocabEntry;

typedef struct {
    double weights[NUM_FEATURES];
    double bias;
    double feat_mean[NUM_FEATURES];
    double feat_std[NUM_FEATURES];
    VocabEntry vocab[VOCAB_SIZE]; 
    int vocab_count;
} Model;

int model_load(Model *m, const char *path);
int vocab_feature(const Model *m, int slot, const char *text);
void full_features_extract(const Model *m, const char *text, double out[NUM_FEATURES]);
void model_standardize(const Model *m, const double raw[NUM_FEATURES], double out[NUM_FEATURES]);
double model_predict_proba(const Model *m, const double raw_features[NUM_FEATURES]);
void strip_newline(char *s);




#endif
