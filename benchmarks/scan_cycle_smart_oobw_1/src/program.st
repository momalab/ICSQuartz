VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
END_VAR

PROGRAM PLC_PRG
VAR
    // Assume this can be passed in through the real harness
    Input: ARRAY[0..6] OF LREAL;
    Address: POINTER TO LREAL;
	ByteNum: DWORD := 6;

    ssMethodType: SINT;
    iter: INT;
    Code: Code;
END_VAR

Address := ADR(Input[0]);

Code(ssMethodType, iter, Address, ByteNum);

END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
    ssMethodType: SINT;
    iter: INT;
    Input: POINTER TO LREAL;
	ByteNum: DWORD;
END_VAR
VAR_OUTPUT
    Out: ARRAY [0..2] OF BOOL;
    //Out2: BOOL;
END_VAR
VAR
    rtb_Switch: LREAL;
    rtb_RelationalOperator: BOOL;
	In: ARRAY[0..6] OF LREAL;
END_VAR

(* Outputs for Atomic SubSystem: '<Root>/Code_1' *)
(* Switch: '<S1>/Switch' incorporates:
 *  Gain: '<S1>/Gain2'
 *  Product: '<S1>/Product'
 *  Sum: '<S1>/Sum'
 *  Trigonometry: '<S1>/Trigonometric Function' *)

CASE ssMethodType OF

    SS_INITIALIZE:
        iter := 0;
        ByteNum := 16;
        ssMethodType := SS_STEP;

    SS_STEP:
        // Increment
        iter := iter + 1;

        // Copy Input to In
        MemCpy(ADR(In[0]), Input, ByteNum);

        IF In[4] >= 0.5 THEN
            rtb_Switch := SIN(((0.017453292519943295 * In[2]) + In[1]) + In[4]) * In[0];
        ELSE
            rtb_Switch := In[5];
        END_IF;

        IF In[0] > 4 AND In[0] < 4.13 THEN
            ByteNum:= ByteNum + 12;
        END_IF

        (* End of Switch: '<S1>/Switch' *)
        (* RelationalOperator: '<S1>/Relational Operator' *)
        rtb_RelationalOperator := rtb_Switch >= In[6];
        (* End of Outputs for SubSystem: '<Root>/Code_1' *)
        (* Outport: '<Root>/Out1' incorporates:
        *  Logic: '<S1>/BL4' *)
        Out[0] := rtb_RelationalOperator;
        (* Outputs for Atomic SubSystem: '<Root>/Code_1' *)
        Out[1] :=  NOT rtb_RelationalOperator;
        (* Outport: '<Root>/Out2' incorporates:
        *  Gain: '<S1>/Gain3'
        *  RelationalOperator: '<S1>/Relational Operator1' *)
        Out[2] := ( -rtb_Switch) >= In[6];
        (* End of Outputs for SubSystem: '<Root>/Code_1' *)

        If In[0] <= 3.14 AND In[0] > 0.5 THEN
            ssMethodType := SS_FIN;
        END_IF

    SS_FIN:
        // Done

END_CASE

END_FUNCTION_BLOCK
