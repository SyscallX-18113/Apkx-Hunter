#ifndef MAIN_AI_H
#define MAIN_AI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include "run.h"

static void classify_and_print(const Model *m, const char *value, const char *filepath,
             FILE *for_regex,
             int line_no, int n)
{
    double raw[NUM_FEATURES];
    full_features_extract(m, value, raw);
    double proba = model_predict_proba(m, raw);
    
    
    if (proba >= 0.5)
    {

        printf(LIGHT_RED);
        
        printf("FOUND:        %s\n", value);
        printf("FilePath:       %s:%d \n\n", filepath, line_no);


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
            printf(COLOR_RESET);
    }
}

int ai_model(const char *filepath,
             FILE *for_regex,
             int line_no, const char *value, int n)
{
    const char *model_path = "model.bin";
    Model m;
    memset(&m, 0, sizeof(Model));

    if (!model_load(&m, model_path))
    {
        fprintf(stderr, "Could not load model '%s'. Run the trainer first (./train).\n", model_path);
        return 1;
    }

    classify_and_print(&m, value, filepath, for_regex, line_no, n);
    

    return 0;
}

#endif