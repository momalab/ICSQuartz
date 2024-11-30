VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
    ArraySize: INT := 7;
END_VAR

PROGRAM PLC_PRG
VAR
    // Assume this can be passed in through the real harness
    In: ARRAY[0..ArraySize] OF DINT := [1, 2, 3, 4, -15, 6, 7, 8];
	In_Bit_Offset: WORD := 0;    // A high enough value here will cause oob read
	ssMethodType: SINT := SS_INITIALIZE;
    iter: INT;
    Code: Code;
END_VAR

Code(ssMethodType, In, In_Bit_Offset);

// First iteration initializes (no oob read), then we call case: SS_STEP, which can cause oob read
IF ssMethodType = SS_INITIALIZE THEN
    ssMethodType:= SS_STEP;
END_IF

END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
    ssMethodType: SINT;
    In_Recv: ARRAY[0..ArraySize] OF DINT;
	In_Bit_Offset: WORD;
END_VAR
VAR_OUTPUT
    y: LREAL;
END_VAR
VAR
	In: ARRAY[0..ArraySize] OF LREAL;
    Integrator_DSTATE: LREAL;
    rtb_Sum4: LREAL;
    CycleCount: DINT;
END_VAR

CASE ssMethodType OF
    SS_INITIALIZE:
        (* SystemInitialize for Atomic SubSystem: '<Root>/Code 1' *)
        (* InitializeConditions for DiscreteIntegrator: '<S34>/Integrator' *)
        Integrator_DSTATE := 0.0;
        (* End of SystemInitialize for SubSystem: '<Root>/Code 1' *)
    SS_STEP:
        // Copy input using pointer and given offset. If offset is out of the input array bounds, this results in an Out-of-Bounds read.
        BitCpy(ADR(In[0]), 0, ADR(In_Recv), In_Bit_Offset, 2 * 8 * SIZEOF(LREAL));
        CycleCount := CycleCount + 1;

        // We also increment In_Bit_Offset which can also cause oob read if base value is high enough
        IF In_Recv[0] >= 375 AND In_Recv[0] < 400 AND In_Recv[3] < 1000 AND In_Recv[3] > 250 AND In_Recv[4] < -10 AND In_Recv[4] > -100 THEN
            IF CycleCount MOD 20 = 0 THEN
                In_Bit_Offset := In_Bit_Offset + 256;
            END_IF
        END_IF

        (* Outputs for Atomic SubSystem: '<Root>/Code 1' *)
        (* Gain: '<S1>/TT - SP Transducer' *)
        rtb_Sum4 := 0.32 * In[0];
        (* Saturate: '<S1>/Sat Block (mA)' *)
        IF rtb_Sum4 >= 4.8 THEN
            rtb_Sum4 := 4.8;
        ELSIF rtb_Sum4 <= -11.2 THEN
            rtb_Sum4 := -11.2;
        END_IF;
        (* End of Saturate: '<S1>/Sat Block (mA)' *)

        IF In_Recv[1] < 30 AND In_Recv[1] > 15 THEN
            ssMethodType := SS_FIN;
        END_IF
        (* Sum: '<S1>/Sum4' *)
        rtb_Sum4 := rtb_Sum4 - In[1];
        (* Outport: '<Root>/y' incorporates:
         *  DiscreteIntegrator: '<S34>/Integrator'
         *  Gain: '<S39>/Proportional Gain'
         *  Sum: '<S43>/Sum' *)
        y := (18.7463 * rtb_Sum4) + Integrator_DSTATE + 1;
        (* Update for DiscreteIntegrator: '<S34>/Integrator' incorporates:
         *  Gain: '<S31>/Integral Gain' *)
        Integrator_DSTATE := ((1.60192 * rtb_Sum4) * 0.05) + Integrator_DSTATE;
        (* End of Outputs for SubSystem: '<Root>/Code 1' *)
    SS_FIN:
        // Done!
END_CASE;

END_FUNCTION_BLOCK
