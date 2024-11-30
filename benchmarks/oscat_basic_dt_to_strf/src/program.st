PROGRAM PLC_PRG
VAR_INPUT
    in_dti: DT;
    in_ms: INT;
    in_lang: INT;
    in_fmt: STRING;
END_VAR

DT_TO_STRF(in_dti, in_ms, in_fmt, in_lang);

END_PROGRAM
