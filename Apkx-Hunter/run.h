#ifndef RUN_H
#define RUN_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include "main_ai.h"


#define NUM_BASE_FEATURES 9
#define PREFIX_LEN 4
#define VOCAB_SIZE 40
#define NUM_FEATURES (NUM_BASE_FEATURES + VOCAB_SIZE)

static double squash(double x, double k) {
    return x / (x + k);
}

static void base_features_extract(const char *s, double out[NUM_BASE_FEATURES]) {
    size_t len = strlen(s);
    memset(out, 0, sizeof(double) * NUM_BASE_FEATURES);
    if (len == 0) return;

    int counts[256] = {0};
    int n_upper = 0, n_lower = 0, n_digit = 0, n_symbol = 0, has_space = 0;
    int longest_alnum_run = 0, current_run = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        counts[c]++;
        if (isupper(c)) n_upper++;
        else if (islower(c)) n_lower++;
        else if (isdigit(c)) n_digit++;
        else if (!isspace(c)) n_symbol++;
        if (isspace(c)) has_space = 1;
        if (isalnum(c)) {
            current_run++;
            if (current_run > longest_alnum_run) longest_alnum_run = current_run;
        } else {
            current_run = 0;
        }
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)len;
        entropy -= p * log2(p);
    }

    int distinct = 0;
    for (int i = 0; i < 256; i++) if (counts[i] > 0) distinct++;

    out[0] = squash((double)len, 30.0);
    out[1] = entropy / 6.5;
    if (out[1] > 1.0) out[1] = 1.0;
    out[2] = (double)n_upper / (double)len;
    out[3] = (double)n_lower / (double)len;
    out[4] = (double)n_digit / (double)len;
    out[5] = (double)n_symbol / (double)len;
    out[6] = has_space ? 1.0 : 0.0;
    out[7] = squash((double)longest_alnum_run, 20.0);
    out[8] = (double)distinct / (double)len;
}


#define MODEL_MAGIC 0x53454352 /* "SECR" */

typedef struct {
    char prefix[PREFIX_LEN + 1];
    double score;
} VocabEntry;

typedef struct {
    double weights[NUM_FEATURES];
    double bias;
    double feat_mean[NUM_FEATURES];
    double feat_std[NUM_FEATURES];
    VocabEntry vocab[VOCAB_SIZE]; /* learned, loaded from model.bin */
    int vocab_count;
} Model;

static double sigmoid(double z) {
    if (z >= 0) {
        double ez = exp(-z);
        return 1.0 / (1.0 + ez);
    } else {
        double ez = exp(z);
        return ez / (1.0 + ez);
    }
}

static int model_load(Model *m, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int magic = 0, nfeat = 0;
    if (fread(&magic, sizeof(int), 1, f) != 1) { fclose(f); return 0; }
    if (fread(&nfeat, sizeof(int), 1, f) != 1) { fclose(f); return 0; }
    if (magic != MODEL_MAGIC || nfeat != NUM_FEATURES) {
        fprintf(stderr, "model_load: incompatible model file '%s'\n", path);
        fclose(f);
        return 0;
    }
    if (fread(m->weights, sizeof(double), NUM_FEATURES, f) != (size_t)NUM_FEATURES) { fclose(f); return 0; }
    if (fread(&m->bias, sizeof(double), 1, f) != 1) { fclose(f); return 0; }
    if (fread(m->feat_mean, sizeof(double), NUM_FEATURES, f) != (size_t)NUM_FEATURES) { fclose(f); return 0; }
    if (fread(m->feat_std, sizeof(double), NUM_FEATURES, f) != (size_t)NUM_FEATURES) { fclose(f); return 0; }
    if (fread(&m->vocab_count, sizeof(int), 1, f) != 1) { fclose(f); return 0; }
    if (fread(m->vocab, sizeof(VocabEntry), VOCAB_SIZE, f) != (size_t)VOCAB_SIZE) { fclose(f); return 0; }
    fclose(f);
    return 1;
}

static int vocab_feature(const Model *m, int slot, const char *text) {
    if (slot >= m->vocab_count) return 0;
    size_t len = strlen(text);
    if (len < (size_t)PREFIX_LEN) return 0;
    return strncmp(text, m->vocab[slot].prefix, PREFIX_LEN) == 0 ? 1 : 0;
}

static void full_features_extract(const Model *m, const char *text, double out[NUM_FEATURES]) {
    double base[NUM_BASE_FEATURES];
    base_features_extract(text, base);
    for (int i = 0; i < NUM_BASE_FEATURES; i++) out[i] = base[i];
    for (int i = 0; i < VOCAB_SIZE; i++) {
        out[NUM_BASE_FEATURES + i] = (double)vocab_feature(m, i, text);
    }
}

static void model_standardize(const Model *m, const double raw[NUM_FEATURES], double out[NUM_FEATURES]) {
    for (int j = 0; j < NUM_FEATURES; j++) {
        out[j] = (raw[j] - m->feat_mean[j]) / m->feat_std[j];
    }
}

static double model_predict_proba(const Model *m, const double raw_features[NUM_FEATURES]) {
    double std_features[NUM_FEATURES];
    model_standardize(m, raw_features, std_features);

    double z = m->bias;
    for (int j = 0; j < NUM_FEATURES; j++) {
        z += m->weights[j] * std_features[j];
    }
    return sigmoid(z);
}


static void strip_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}


#endif
