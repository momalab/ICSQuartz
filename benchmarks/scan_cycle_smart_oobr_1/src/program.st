VAR_GLOBAL CONSTANT
    SS_INITIALIZE: SINT := 0;
    SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
END_VAR

PROGRAM PLC_PRG
VAR
    // Assume this can be passed in through the real harness
    In: ARRAY[0..1] OF LREAL;
	In_Bit_Offset: WORD;    // A high enough value here will cause oob read

	ssMethodType: SINT := SS_INITIALIZE;
    iter: INT;
    Code: Code;
END_VAR

Code(ssMethodType, In, In_Bit_Offset);

END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
    ssMethodType: SINT;
    In_Recv: ARRAY[0..1] OF LREAL;
	In_Bit_Offset: WORD;
END_VAR
VAR_OUTPUT
    x: LREAL;
END_VAR
VAR
    Square: LREAL;
    Filter_DSTATE: LREAL;
    Integrator_DSTATE: LREAL;

    rtb_Subtract: LREAL;
    rtb_FilterCoefficient: LREAL;

	In1: ARRAY[0..1] OF LREAL;
END_VAR

CASE ssMethodType OF
    SS_INITIALIZE:
        (* SystemInitialize for Atomic SubSystem: '<Root>/Code 2' *)
        (* InitializeConditions for DiscreteIntegrator: '<S29>/Filter' *)
        Filter_DSTATE := 0.0;
        (* InitializeConditions for DiscreteIntegrator: '<S34>/Integrator' *)
        Integrator_DSTATE := 0.0;
        (* End of SystemInitialize for SubSystem: '<Root>/Code 2' *)

        (* ConstCode for Atomic SubSystem: '<Root>/Code 2' *)
        (* ConstCode for Math: '<S1>/Square' incorporates:
         *  Constant: '<S1>/Constant' *)
        Square := 458751.02394617227;
        (* End of ConstCode for SubSystem: '<Root>/Code 2' *)
        ssMethodType := SS_STEP;
    SS_STEP:
        BitCpy(ADR(In1[0]), 0, ADR(In_Recv), In_Bit_Offset, 8 * SIZEOF(LREAL));

        IF In_Recv[0] > 3.14 AND In_Recv[0] < 30.13 THEN
            In_Bit_Offset:= In_Bit_Offset + 400;
        END_IF
        (* Outputs for Atomic SubSystem: '<Root>/Code 2' *)
        (* Sum: '<S1>/Subtract' incorporates:
         *  Math: '<S1>/Square1' *)
        rtb_Subtract := Square - (In1[0] * In1[0]);
        (* Gain: '<S37>/Filter Coefficient' incorporates:
         *  DiscreteIntegrator: '<S29>/Filter'
         *  Gain: '<S28>/Derivative Gain'
         *  Sum: '<S29>/SumD' *)
        rtb_FilterCoefficient := ((0.10932922971946307 * rtb_Subtract) - Filter_DSTATE) * 3.8620401712747761;
        (* Outport: '<Root>/y' incorporates:
         *  DiscreteIntegrator: '<S34>/Integrator'
         *  Gain: '<S39>/Proportional Gain'
         *  Sum: '<S43>/Sum' *)
        x := ((2.5899754807860003 * rtb_Subtract) + Integrator_DSTATE) + rtb_FilterCoefficient;
        (* Update for DiscreteIntegrator: '<S29>/Filter' *)
        Filter_DSTATE := (5.0E-6 * rtb_FilterCoefficient) + Filter_DSTATE;
        (* Update for DiscreteIntegrator: '<S34>/Integrator' incorporates:
         *  Gain: '<S31>/Integral Gain' *)
        Integrator_DSTATE := ((19.365373103211319 * rtb_Subtract) * 5.0E-6) + Integrator_DSTATE;
        (* End of Outputs for SubSystem: '<Root>/Code 2' *)

        If In_Recv[0] <= 3.14 AND In_Recv[0] > 0.5 THEN
            ssMethodType := SS_FIN;
        END_IF
    SS_FIN:
        // Do nothing
END_CASE;

END_FUNCTION_BLOCK
