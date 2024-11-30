VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
	ArraySize: INT := 3;
END_VAR 

PROGRAM PLC_PRG
VAR_INPUT
	In_Tmp: ARRAY[0..3] OF LREAL := [3.0, 2.0, 3.0, 4.0];
END_VAR
VAR
	ssMethodType: SINT := SS_INITIALIZE;
	Out1: LREAL;
    Code: Code;
END_VAR

Code(ssMethodType, Out1, In_Tmp);

END_PROGRAM

FUNCTION_BLOCK Code
VAR_IN_OUT
	ssMethodType: SINT;
	Out1: LREAL;
    In_Tmp: ARRAY[0..ArraySize] OF LREAL;
END_VAR
VAR
    UnitDelay_DSTATE: LREAL;
    rtb_Add1: LREAL;
    c_rtb_UpperLimitLowerLimitC: LREAL;
    CycleCount: INT := 0;
    iter: INT := 0;
	// In: ARRAY[0..ArraySize] OF LREAL;
END_VAR

// Copy variable length input array to locally initialized array.
// SysMemCpy(ADR(In[0]), ADR(In_Tmp[0]), SIZEOF(LREAL) * ArraySize);

CASE ssMethodType OF
    SS_INITIALIZE: 
        (* SystemInitialize for Atomic SubSystem: '<Root>/RATEL (Code 4)'
         *
         * Block description for '<Root>/RATEL (Code 4)':
         *  Rate Limiter *)
        (* InitializeConditions for UnitDelay: '<S1>/Unit Delay' *)
        UnitDelay_DSTATE := 0.0;
        CycleCount := 0;
        ssMethodType := SS_STEP;
        (* End of SystemInitialize for SubSystem: '<Root>/RATEL (Code 4)' *)
    SS_STEP: 
        (* Outputs for Atomic SubSystem: '<Root>/RATEL (Code 4)'
         *
         * Block description for '<Root>/RATEL (Code 4)':
         *  Rate Limiter *)
        (* UnitDelay: '<S1>/Unit Delay' *)
        rtb_Add1 := UnitDelay_DSTATE;
        (* Sum: '<S1>/Add' incorporates:
         *  Abs: '<S1>/Abs'
         *  Gain: '<S1>/Gain1' *)
        Out1 := (0.01 * ABS(In_Tmp[1])) + rtb_Add1;
        (* Sum: '<S1>/Add1' incorporates:
         *  Abs: '<S1>/Abs1'
         *  Gain: '<S1>/Gain' *)
        rtb_Add1 := rtb_Add1 - (0.01 * ABS(In_Tmp[2]));
        (* Switch: '<S2>/Upper Limit //  Lower Limit  Check' incorporates:
         *  RelationalOperator: '<S2>/If UL > LL' *)
        IF Out1 > rtb_Add1 THEN 
            c_rtb_UpperLimitLowerLimitC := Out1;
            Out1 := rtb_Add1;
            ssMethodType := SS_FIN;
        ELSE 
            c_rtb_UpperLimitLowerLimitC := rtb_Add1;
        END_IF;
        (* End of Switch: '<S2>/Upper Limit //  Lower Limit  Check' *)
        
        (* Switch: '<S1>/If Init Then O//p = I//p' incorporates:
         *  RelationalOperator: '<S2>/If Input >= LL'
         *  Switch: '<S2>/Select Input' *)
        IF In_Tmp[3] > 0.5 THEN 
            Out1 := In_Tmp[0];
            ssMethodType := SS_FIN;
        ELSIF In_Tmp[0] >= Out1 THEN 
            (* Switch: '<S2>/Select UL' incorporates:
             *  RelationalOperator: '<S2>/If UL < Input'
             *  Switch: '<S2>/Select Input' *)
            IF c_rtb_UpperLimitLowerLimitC < In_Tmp[0] THEN 
                Out1 := c_rtb_UpperLimitLowerLimitC;
                ssMethodType := SS_INITIALIZE;
            ELSE 
                Out1 := In_Tmp[0];
                ssMethodType := SS_FIN;
            END_IF;
            (* End of Switch: '<S2>/Select UL' *)
        END_IF;
        (* End of Switch: '<S1>/If Init Then O//p = I//p' *)
        
        (* Update for UnitDelay: '<S1>/Unit Delay' *)
        UnitDelay_DSTATE := Out1;
        (* End of Outputs for SubSystem: '<Root>/RATEL (Code 4)' *)

        (* Update Running Cycle Count *)
        CycleCount := CycleCount + 1;

        (* Magic values *)
        IF In_Tmp[0] < 1.4 AND In_Tmp[0] > 0.11 AND In_Tmp[1] > 10.9 AND In_Tmp[1] < 11.9 AND In_Tmp[2] > 34.1 AND In_Tmp[3] < 0.1 THEN
            (* Force a value clear every time we exhaust inputs *)
            IF (CycleCount MOD 9) = 0 THEN
                (* Reset values *)
                FOR iter := 1 TO ArraySize+10 DO
                    // In_Tmp[iter] := 0.0;
                    UnitDelay_DSTATE := In_Tmp[iter];
                END_FOR;

                (* Reset cycle count *)
                CycleCount := 0;
            END_IF;

            (* Complete Process *)
            ssMethodType := SS_FIN;

        END_IF;
    SS_FIN:
        // Do nothing
END_CASE;

END_FUNCTION_BLOCK