table_3_part_1 = {
    "compiler": "latest",
    "scan_cycle": False,
    "asan_alternate": True,
    "benchmarks": [
        "icsfuzz_bf_mcpy_1",
        "icsfuzz_bf_mcpy_6",
        "icsfuzz_bf_mcpy_8",
        "icsfuzz_bf_mcpy_12",
        "icsfuzz_bf_mmove_1",
        "icsfuzz_bf_mmove_4",
        "icsfuzz_bf_mmove_7",
        "icsfuzz_bf_mmove_12",
        "icsfuzz_bf_mset_1",
        "icsfuzz_bf_mset_3",
        "icsfuzz_bf_mset_5",
    ],
    "results": ["latest-per-benchmark.csv"],
    "results_columns": ["execs_per_sec", "first_crash_time", "first_crash_executions"],
}

table_3_part_2 = {
    "compiler": "latest",
    "scan_cycle": False,
    "asan_alternate": False,
    "benchmarks": [
        "icsfuzz_oob_1_arr_1",
        "icsfuzz_oob_1_arr_6",
        "icsfuzz_oob_1_arr_13",
        "icsfuzz_oob_2_1",
        "icsfuzz_oob_2_5",
        "icsfuzz_oob_2_13",
    ],
    "results": ["latest-per-benchmark.csv"],
    "results_columns": ["execs_per_sec", "first_crash_time", "first_crash_executions"],
}

table_4 = {
    "compiler": "latest",
    "scan_cycle": True,
    "asan_alternate": False,
    "benchmarks": [
        "scan_cycle_aircraft_oobr",
        "scan_cycle_aircraft_oobw_4",
        "scan_cycle_aircraft_oobw_5",
        "scan_cycle_anaerobic_oobr_1",
        "scan_cycle_anaerobic_oobr_2",
        "scan_cycle_anaerobic_oobw_1",
        "scan_cycle_anaerobic_oobw_2",
        "scan_cycle_anaerobic_oobw_3",
        "scan_cycle_chemical_oobr_1",
        "scan_cycle_chemical_oobw_1",
        "scan_cycle_smart_oobr_1",
        "scan_cycle_smart_oobw_1",
    ],
    "results": ["latest-all.csv"],
    "results_columns": [
        "trial",
        "first_crash_time",
        "first_crash_executions",
    ],
}


table_5 = {
    "compiler": "latest",
    "scan_cycle": True,
    "asan_alternate": False,
    "benchmarks": [
        "scan_cycle_aircraft_oobr",
        "scan_cycle_aircraft_oobw_4",
        "scan_cycle_aircraft_oobw_5",
        "scan_cycle_anaerobic_oobr_1",
        "scan_cycle_anaerobic_oobr_2",
        "scan_cycle_anaerobic_oobw_1",
        "scan_cycle_anaerobic_oobw_2",
        "scan_cycle_anaerobic_oobw_3",
        "scan_cycle_chemical_oobr_1",
        "scan_cycle_chemical_oobw_1",
        "scan_cycle_smart_oobr_1",
        "scan_cycle_smart_oobw_1",
    ],
    "results": ["latest-all.csv"],
    "results_columns": [
        "trial",
        "execs_total",
        "first_crash_time",
        "state_resets",
    ],
}

table_7_oscat_basic = {
    "compiler": "bug",
    "scan_cycle": False,
    "asan_alternate": True,
    "benchmarks": [
        "oscat_basic_charname",
        "oscat_basic_clean",
        "oscat_basic_del_chars",
        "oscat_basic_dt_to_strf",
        "oscat_basic_findb_nonum",
        "oscat_basic_findb_num",
        "oscat_basic_find_char",
        "oscat_basic_find_ctrl",
        "oscat_basic_fstring_to_byte",
        "oscat_basic_fstring_to_dword",
        "oscat_basic_is_cc",
        "oscat_basic_is_ncc",
        "oscat_basic_mirror",
        "oscat_basic_month_to_string",
        "oscat_basic_real_to_strf",
        "oscat_basic_replace_all",
        "oscat_basic_replace_chars",
        "oscat_basic_trim",
        "oscat_basic_trim1",
        "oscat_basic_trime",
        "oscat_basic_upper_case",
        "oscat_basic_weekday_to_string",
    ],
    "results": ["latest-per-benchmark.csv"],
    "results_columns": [
        "execs_total",
    ],
}

table_7_oscat_network = {
    "compiler": "bug",
    "scan_cycle": False,
    "asan_alternate": True,
    "benchmarks": [
        "oscat_network_base64_encode_str",
        "oscat_network_xml_reader",
    ],
    "results": ["latest-per-benchmark.csv"],
    "results_columns": [
        "execs_total",
    ],
}

cve = {
    "compiler": "bug",
    "scan_cycle": False,
    "asan_alternate": False,
    "benchmarks": [
        "oscat_basic_month_to_string",
    ],
    "results": ["latest-all.csv"],
    "results_columns": ["first_crash_time"],
}
