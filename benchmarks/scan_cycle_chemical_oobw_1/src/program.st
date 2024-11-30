VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
END_VAR

PROGRAM PLC_PRG
VAR
	In1: ARRAY [0..40] OF LREAL;
    In2: ARRAY [0..40] OF LREAL;
    ssMethodType: SINT := SS_INITIALIZE;
	perhr: LREAL;

    iter: INT;
    idx: INT;
    size: INT := 5;
    Code: Code;
END_VAR

Code(ssMethodType, iter, size, In1, In2, perhr);

END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
    ssMethodType: SINT;
    iter: INT;
    size: INT;
    In1_Arg: ARRAY [0..40] OF LREAL;
    In2_Arg: ARRAY [0..40] OF LREAL;
END_VAR
VAR_INPUT
    // In1_Arg: POINTER TO ARRAY [0..20] OF LREAL;
    // In2_Arg: POINTER TO ARRAY [0..20] OF LREAL;
    perhr: LREAL;
END_VAR
VAR
	In1: ARRAY [0..40] OF LREAL;
    In2: ARRAY [0..40] OF LREAL;

    Gain2_Gain: ARRAY [0..6] OF LREAL := [2.209,6.177,22.06,14.56,17.89,30.44,22.94];

    In1_0: ARRAY [0..6] OF LREAL;
    tmp: LREAL;
    i: DINT;
END_VAR


// Copy Input Arrays. Because we use dynamic arrays and get their upper bound on runtime,
// if the caller passes arrays with a larger size than the preallocated local arrays, this will result in an Out-of-Bounds write.
MemCpy(ADR(In1[0]), ADR(In1_Arg[0]), size * SIZEOF(LREAL));
MemCpy(ADR(In2[0]), ADR(In2_Arg[0]), size * SIZEOF(LREAL));

CASE ssMethodType OF

    SS_INITIALIZE:
        In1[0] := 0.0;
        ssMethodType := SS_STEP;

    SS_STEP:
        (* Outputs for Atomic SubSystem: '<Root>/Code 2' *)
        (* SignalConversion: '<S2>/TmpSignal ConversionAtGain2Inport1' *)
        In1_0[4] := In1[28];
        FOR i := 0 TO 5 DO
            In1_0[i + 1] := In1[i + 30];
        END_FOR;
        (* End of SignalConversion: '<S2>/TmpSignal ConversionAtGain2Inport1' *)
        (* Gain: '<S2>/Gain2' *)
        tmp := 0.0;
        FOR i := 0 TO 6 DO
            tmp := (Gain2_Gain[i] * In1_0[i]) + tmp;
        END_FOR;

        iter := iter + 1;
        // size := size + 1;
        // printf('size: %d$N', size);
        // print in1_arg0
        // printf('In1_Arg[0]: %f$N', In1_Arg[0]);
        IF In1_Arg[0] > 0.14 AND In1_arg[0] < 20.13 THEN
            size := size + 100;
        END_IF

        (* Outport: '<Root>/$ per hr' incorporates:
        *  Gain: '<S2>/Gain'
        *  Gain: '<S2>/Gain1'
        *  Gain: '<S2>/Gain2'
        *  Gain: '<S2>/Gain3'
        *  Gain: '<S2>/Gain4'
        *  Product: '<S2>/Product'
        *  Product: '<S2>/Product1'
        *  Sum: '<S2>/Sum' *)
        perhr := ((((0.2206 * In1[36]) + (0.1456 * In1[37])) + (0.1789 * In1[38])) * (4.541 * In2[7])) + (((0.0318 * In1[18]) + (0.0536 * In1[19])) + ((0.44791 * In1[9]) * tmp));
        (* End of Outputs for SubSystem: '<Root>/Code 2' *)

        If In1_Arg[0] <= 3.14 AND In1_Arg[0] > 0 THEN
            ssMethodType := SS_FIN;
        END_IF

    SS_FIN:
        // Do nothing
END_CASE

END_FUNCTION_BLOCK
