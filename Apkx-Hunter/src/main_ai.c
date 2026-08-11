/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "main_ai.h"

Model m;
const char *model_path = "model.bin";

int model_init(void)
{

    
    
    const char *paths[] = {
        "model.bin",
        "/usr/share/apkx-hunter/model.bin",
        "model/model.bin"};

    const size_t path_count = sizeof(paths) / sizeof(paths[0]);

    memset(&m, 0, sizeof(m));

    for (size_t i = 0; i < path_count; i++)
    {
        if (model_load(&m, paths[i]))
        {
            model_path = paths[i];

            printf(HACKER_WHITE "Loaded model from: %s\n" COLOR_RESET, model_path);
            return 1;
        }

        memset(&m, 0, sizeof(m));
    }

    printf(HACKER_WHITE "Could not load model.bin. Checked:\n  - %s\n  - %s\n  - %s\n" COLOR_RESET,
            paths[0], paths[1], paths[2]);

    return 0;
}

void classify_and_print(const Model *m, const char *value, const char *filepath,
                        FILE *for_regex,
                        int line_no, int n)
{
    double raw[NUM_FEATURES];
    full_features_extract(m, value, raw);
    double proba = model_predict_proba(m, raw);

    if (proba >= 0.5)
    {

        printf(LIGHT_RED);
        if (silent_mode == 1)
        {
            printf("FOUND:        %s\n", value);
            printf("FilePath:       %s:%d \n\n", filepath, line_no);
        }

        fprintf(
            for_regex,
            "Secret_Type: %s\n"
            "Severity: %s\n"
            "File: %s:%d\n"
            "Secret Value: %s\n\n",
            secrets[n].name,
            secrets[n].severity,
            filepath,
            line_no,
            value);
        stats.secrets++;
        printf(COLOR_RESET);
    }
}

int ai_model(const char *filepath,
             FILE *for_regex,
             int line_no, const char *value, int n)
{

    classify_and_print(&m, value, filepath, for_regex, line_no, n);

    return 0;
}
