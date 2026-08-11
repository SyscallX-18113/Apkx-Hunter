/*
 * Copyright (c) 2026 Devesh Kachhawaha (SyscallX-18113)
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the project root for license information.
 */

#include "banner.h"

void print_banner(void)
{
    printf(LIGHT_RED);
    printf("\t                                                             \n");
    printf("\t                                                             \n");
    printf("\t                                                             \n");
    printf("\t          .... NO! ...                  ... MNO! ...           \n");
    printf("\t         ..... MNO!! ...................... MNNOO! ...         \n");
    printf("\t       ..... MMNO! ......................... MNNOO!! .         \n");
    printf("\t      ..... MNOONNOO!   MMMMMMMMMMPPPOII!   MNNO!!!! .         \n");
    printf("\t       ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....           \n");
    printf("\t          ...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...             \n");
    printf("\t         ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....            \n");
    printf("\t         ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...              \n");
    printf("\t          ....... MMMMM..    OPPMMP    .,OMI! ....             \n");
    printf("\t           ...... MMMM::   o.,OPMP,.o   ::I!! ...              \n");
    printf("\t               .... NNM:::.,,OOPM!P,.::::!! ....               \n");
    printf("\t                .. MMNNNNNOOOOPMO!!IIPPO!!O! .....             \n");
    printf("\t               ... MMMMMNNNNOO:!!:!!IPPPPOO! ....              \n");
    printf("\t                ...... MMMONNMMNNNIIIOO!..........             \n");
    printf("\t             ....... MN MOMMMNNNIIIIIO! OO ..........          \n");
    printf("\t          ......... MNO! IiiiiiiiiiiiI OOOO ...........        \n");
    printf("\t        ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........      \n");
    printf("\t         .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........       \n");
    printf("\t         ...... MNNNNO! .. PPPPPPPPP .. MMNON!........         \n");
    printf("\t            ...... OO! ................. ON! .......           \n");
    printf("\t               ................................                \n");
    printf("\t                                                               \n");
    printf("\t                      SyscallX-18113                           \n");
    printf("\n");
    printf("\n");
    printf(LIGHT_YELLOW "\n");
    printf("                                                                   \n");
    printf("\t═════════════════════════════════════════════════════════════════════════\n");
    printf("\t                                                              \n");
    printf("\t      ___        _                 _   _             _            \n");
    printf("\t     / _ \\      | |               | | | |           | |           \n");
    printf("\t    / /_\\ \\_ __ | | ____  ________| |_| |_   _ _ __ | |_ ___ _ __ \n");
    printf("\t    |  _  | '_ \\| |/ /\\ \\/ /______|  _  | | | | '_ \\| __/ _ \\ '__|\n");
    printf("\t    | | | | |_) |   <  >  <       | | | | |_| | | | | ||  __/ |   \n");
    printf("\t    \\_| |_/ .__/|_|\\_\\/_/\\_\\      \\_| |_/\\__,_|_| |_|\\__\\___|_|   \n");
    printf("\t          | |                                                     \n");
    printf("\t          |_|              \n");
    printf("\t                                                              \n");
    printf("\t                                                              \n");
    printf("\t    Android Reverse Engineering And APK Static Analysis Framework\n");
    printf("\t                                                              \n");
    printf("\t                                                              \n");
    printf("\t           • OWASP MASVS Detection • jadx • apktool                           \n");
    printf("\t                                                              \n");
    printf("\t                 Developed by SyscallX-18113                     \n");
    printf("\t                                                              \n");
    printf("\t                         v2.7.1                                     \n");
    printf("\t                                                              \n");
    printf("\t═════════════════════════════════════════════════════════════════════════\n\n\n");
    printf(COLOR_RESET);
}

void help_func()
{
    printf(HACKER_WHITE);
    printf(
        "\n"
        "═════════════════════════════════════════════════════════════════════════════\n"
        "                         APKX-Hunter v2.7.1\n\n"
        "           Github: https://github.com/SyscallX-18113/Apkx-Hunter\n\n"
        "               - Android Static Analysis Framework written in C\n\n"
        "         - Enhanced command-line argument parsing and flag validation\n"
        "═════════════════════════════════════════════════════════════════════════════\n"
        "\n"
        "< USAGE >\n"
        "  ./apkx_hunter <package/folder> [options] [options]\n"
        "-------------------------------------------------------------\n"
        "\n"
        "< GENERAL OPTIONS: >\n"
        "  --help                     Show help message.\n\n"

        "Dependency Management:\n"
        "--install-dependencies     Automatically check and install JADX, Apktool, Java, and other required tools.\n"
        "-------------------------------------------------------------\n"
        "\n"

        "< SCANNING MODES FOR JADX: > \n"
        "  --fast                 Perform a fast jadx decompilation and scan extracted folder.\n"
        "  --deep                 Perform a complete deep jadx decompilation and scan extracted folder.\n"
        "\n"
        "Note: Use these flags only after giving apk file name\n"
        "\n"
        "Examples:\n"
        "./apkxhunter app.apk --fast\n"
        "./apkxhunter app.apk --deep\n"
        "-------------------------------------------------------------\n"
        "\n"
        
        "< SCANNING MODES FOR APKTOOL: >\n"
        "  --apktool               Perform a apktool decompilation and scan extracted folder.\n"
        "\n"
        "Note: Use these flags only after giving apkfile name\n"
        "\n"
        "Examples:\n"
        "./apkxhunter app.apk --apktool\n"
        "-------------------------------------------------------------\n"
        "\n"

        "< MULTI APK SCANNING MODE FROM FOLDER: >\n"
        "  --multi-apk             Perform a multi apk decompilation and scan extracted folder.\n"
        "\n"
        "Note: Use these flags only after giving apk_files_folder name\n"
        "\n"
        "Examples:\n"
        "./apkxhunter Apks --multi-apk\n"
        "-------------------------------------------------------------\n"
        "\n"

        "< APK PACKAGE SCANNNING MODE: >\n"
        "  --extract-multi-apk    Extract package (APKS/APKM/XAPK/ZIP) and automatically analyze every extracted APK.\n"
        "\n"
        "Note: Use these flags only after giving apk_package_file name\n"
        "\n"
        "Examples:\n"
        "./apkxhunter test.apkm --extract-multi-apk\n"
        "-------------------------------------------------------------\n"
        "\n"

        "< FOLDER ANALYSIS: >\n"
        "  --folder-scan          Scan an already decompiled JADX source directory or any directory\n"
        "  --apktool-folder-scan  Scan an already decompiled Apktool directory use this flag only for scanning decompiled apk folder which is decompiled by APKTOOL.\n"
        "\n"
        "Note: Use these flags only after folder_name for scan\n"
        "\n"
        "Examples:\n"
        "./apkxhunter <folder_name> --folder-scan\n"
        "./apkxhunter <folder_name_decompiled_by_apktool> --apktool-folder-scan\n"
        "-------------------------------------------------------------\n"
        "\n"
        

        "< INDIVIDUAL SCANNERS: >\n"
        "  --secrets              Scan for API keys, tokens, passwords, and other embedded secrets.\n"
        "  --permissions          Analyze Android permissions or exported activity.\n"
        "  --endpoints            Discover URLs, endpoints, and patterns.\n"
        "  --files                Generate a file inventory report with .so name files extraction.\n"
        "  --masvs                OWASP MASVS Scan.\n"
        "\n"
        "Note: Use these flags only after scanning modes flags or folder analysis flags\n"
        "\n"
        "Examples:\n"
        "./apkxhunter app.apk --deep --secrets\n"
        "./apkxhunter Apks_folder --deep --multi-apk --secrets\n"
        "./apkxhunter test.apkm --extract-multi-apk --secrets\n"
        "./apkxhunter app.apk --deep --masvs\n"
        "./apkxhunter <folder_name> --folder-scan --secrets\n"
        "./apkxhunter <folder_name> --folder-scan --permissions\n"
        "./apkxhunter <folder_name_decompiled_by_apktool> --apktool-folder-scan --endpoints\n"
        "./apkxhunter app.apk --deep --files\n"
        "-------------------------------------------------------------\n"
        "\n"
        

        "< DECOMPILATION ONLY: > \n"
        
        "  --decompile            Decompile APK using JADX or APKTOOL doesn't run folder scan after decompilation\n"
        "\n"
        "Note: Use these flags only after scanning modes flags\n"
        "\n"
        "Examples:\n"
        "./apkxhunter app.apk --deep --decompile\n"
        "-------------------------------------------------------------\n"
        "\n"
        

        "< ARCHIVE SUPPORT: >\n"
        "  --extract              Extract supported Android packages before analysis and save extracted apk to folder extracted_output_<apk_name>.\n"
        "Supported Formats:\n"
        "  APKM, APKS, XAPK, ZIP\n"
        "Example:\n"
        "./apkxhunter app.apkm --extract\n"
        "-------------------------------------------------------------\n"
        "\n\n"
        "< OUTPUT DIRECTORY STRUCTURE: >\n"
        "\n"
        "JADX Analysis:\n"
        "    Jadx_output_<apk_name>/\n\n"
        " Findins Reports:\n"
        "    Result_Jadx_output_<apk_name>/\n"
        "      |- secrets_findings.txt      -> Embedded API keys, tokens, secrets\n"
        "      |- permissions_findings.txt  -> Android permission analysis\n"
        "      |- pattern_findings.txt      -> URLs, endpoints and security patterns\n"
        "      |- files.txt                 -> File inventory report\n"
        "      |- native_library_files.txt  -> Detected native (.so) libraries\n"
        "      |- masvs_findings.txt        -> OWASP MASVS Scann Result\n\n"

        "Folder Scan Result:\n"
        "\n"
        " Findings Reports:\n"
        "    Folder-Scan_Result_<folder_name>/\n"
        "      |- secrets_findings.txt\n"
        "      |- permissions_findings.txt\n"
        "      |- pattern_findings.txt\n"
        "      |- files.txt\n"
        "      |- native_library_files.txt\n"
        "      |- masvs_findings.txt\n\n"


        "APKTool Analysis:\n"
        "\n"
        "    Apktool_output_<apk_name>/\n\n"

        " Findings Reports:\n"
        "    Apktool_Result_<apk_name>/\n"
        "      |- secrets_findings.txt\n"
        "      |- permissions_findings.txt\n"
        "      |- pattern_findings.txt\n"
        "      |- files.txt\n"
        "      |- native_library_files.txt\n"
        "      |- masvs_findings.txt\n"

        "APKTOOL Folder Scan Result:\n"
        "\n"
        " Findings Reports:\n"
        "    Apktool-folder-scan_Result_<folder_name>/\n"
        "      |- secrets_findings.txt\n"
        "      |- permissions_findings.txt\n"
        "      |- pattern_findings.txt\n"
        "      |- files.txt\n"
        "      |- native_library_files.txt\n"
        "      |- masvs_findings.txt\n"

        "Archive Extraction:\n"
        "  extracted_output_<package_name>/\n"
        "      |- Extracted APK files\n"
        "\n"
        
        "\n"
        "══════════════════════════════════════════════════════════════\n"
        "  APKX Hunter v2.7.1\n"
        "  Developed by SyscallX-18113\n"
        "══════════════════════════════════════════════════════════════\n");

    printf(COLOR_RESET);

    
}
