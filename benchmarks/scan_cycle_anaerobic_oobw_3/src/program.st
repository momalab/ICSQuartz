VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
END_VAR


PROGRAM PLC_PRG
VAR
    // Assume this can be passed in through the real harness
    In1: LREAL;
	In1_Size: WORD;

	ssMethodType: SINT;
    iter: INT;
    Code: Code;
END_VAR

Code(ssMethodType, In1_Size, ADR(In1));

END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
	ssMethodType: SINT;
	In1_Size: WORD;
END_VAR
VAR_INPUT
    In1_Ptr: POINTER TO LREAL;
END_VAR
VAR_OUTPUT
    Out1: LREAL;
END_VAR
VAR
	In1: LREAL;
END_VAR

CASE ssMethodType OF

    SS_INITIALIZE:
        // Initialize
        In1 := 0.0;
        Out1 := 0.0;
        In1_Size := 1;
        ssMethodType := SS_STEP;

    SS_STEP:

        // Move input. Using a large size results in an Out of Bounds read/write
        SysMemMove(ADR(In1), In1_Ptr, In1_Size);
        // printf('In1_Size: %d$N', In1_Size);
        // In1_Size := In1_Size + 1;

        (* Outputs for Atomic SubSystem: '<Root>/Code 3' *)
        (* Gain: '<S1>/T-Sensor' *)
        IF In1 <= 0.0 AND In1 >= -10.14 THEN
            Out1 := 0.32 * In1;
            In1_Size := In1_Size + 1;
        END_IF

        Out1 := 0.32 * In1;
        (* Saturate: '<S1>/Sat Block (mA) - S' *)
        IF Out1 >= 4.8 THEN
            (* Outport: '<Root>/Out1' *)
            Out1 := 4.8;
        ELSIF Out1 <= -11.2 THEN
            (* Outport: '<Root>/Out1' *)
            Out1 := -11.2;
        END_IF;
        (* End of Saturate: '<S1>/Sat Block (mA) - S' *)
        (* End of Outputs for SubSystem: '<Root>/Code 3' *)

        IF In1 < 3.14 AND In1 > 0 THEN
            ssMethodType := SS_FIN;
        END_IF

    SS_FIN:
        // Done :)
END_CASE

END_FUNCTION_BLOCK
