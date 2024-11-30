VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
END_VAR

PROGRAM PLC_PRG
VAR
	In_Tmp: ARRAY[0..20] OF LREAL;
    Out1: LREAL;
    bytesToCopy: DWORD := 32;

	ssMethodType: SINT := SS_INITIALIZE;
    Code: Code;
END_VAR

Code(ssMethodType, Out1, In_Tmp, bytesToCopy);

END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
	ssMethodType: SINT;
	Out1: LREAL;
    In_Tmp: ARRAY[0..20] OF LREAL;
    bytesToCopy: DWORD;
END_VAR
VAR

	In: ARRAY[0..9] OF LREAL;

    UnitDelay_DSTATE: LREAL;

    rtb_Add1: LREAL;
    c_rtb_UpperLimitLowerLimitC: LREAL;
    iter: INT;
END_VAR

CASE ssMethodType OF
    SS_INITIALIZE:
        (* SystemInitialize for Atomic SubSystem: '<Root>/RATEL (Code 4)'
         *
         * Block description for '<Root>/RATEL (Code 4)':
         *  Rate Limiter *)
        (* InitializeConditions for UnitDelay: '<S1>/Unit Delay' *)
        UnitDelay_DSTATE := 0.0;
        ssMethodType := SS_STEP;
        (* End of SystemInitialize for SubSystem: '<Root>/RATEL (Code 4)' *)
    SS_STEP:
        // Copy variable length input array to locally initialized array.
        // This causes an out of bounds write if the input array length is greater than the local one. (Correct patch input: 40)
        iter := iter + 1;
        SysMemCpy(ADR(In[0]), ADR(In_Tmp[0]), bytesToCopy);

        (* Outputs for Atomic SubSystem: '<Root>/RATEL (Code 4)'
         *
         * Block description for '<Root>/RATEL (Code 4)':
         *  Rate Limiter *)
        (* UnitDelay: '<S1>/Unit Delay' *)
        rtb_Add1 := UnitDelay_DSTATE;
        (* Sum: '<S1>/Add' incorporates:
         *  Abs: '<S1>/Abs'
         *  Gain: '<S1>/Gain1' *)
        Out1 := (0.01 * ABS(In[1])) + rtb_Add1;
        (* Sum: '<S1>/Add1' incorporates:
         *  Abs: '<S1>/Abs1'
         *  Gain: '<S1>/Gain' *)
        rtb_Add1 := rtb_Add1 - (0.01 * ABS(In[2]));
        (* Switch: '<S2>/Upper Limit //  Lower Limit  Check' incorporates:
         *  RelationalOperator: '<S2>/If UL > LL' *)
        IF Out1 > rtb_Add1 THEN
            c_rtb_UpperLimitLowerLimitC := Out1;
            Out1 := rtb_Add1;
        ELSE
            c_rtb_UpperLimitLowerLimitC := rtb_Add1;
        END_IF;
        (* End of Switch: '<S2>/Upper Limit //  Lower Limit  Check' *)

        (* Switch: '<S1>/If Init Then O//p = I//p' incorporates:
         *  RelationalOperator: '<S2>/If Input >= LL'
         *  Switch: '<S2>/Select Input' *)
        IF In[3] > 0.5 THEN
            Out1 := In[0];
        ELSIF In[0] >= Out1 THEN
            (* Switch: '<S2>/Select UL' incorporates:
             *  RelationalOperator: '<S2>/If UL < Input'
             *  Switch: '<S2>/Select Input' *)
                IF In[1] > 3.14 AND In[1] < 30.28 THEN
                    bytesToCopy := SIZEOF(LREAL) * (iter + 1);
                END_IF
            IF c_rtb_UpperLimitLowerLimitC < In[0] THEN
                Out1 := c_rtb_UpperLimitLowerLimitC;
            ELSE
                Out1 := In[0];
            END_IF;
            (* End of Switch: '<S2>/Select UL' *)
        END_IF;
        (* End of Switch: '<S1>/If Init Then O//p = I//p' *)

        (* Update for UnitDelay: '<S1>/Unit Delay' *)
        UnitDelay_DSTATE := Out1;
        (* End of Outputs for SubSystem: '<Root>/RATEL (Code 4)' *)
    SS_FIN:
        // Do nothing
END_CASE;

END_FUNCTION_BLOCK
