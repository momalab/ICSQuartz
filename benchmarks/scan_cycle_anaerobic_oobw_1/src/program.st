VAR_GLOBAL CONSTANT
	SS_INITIALIZE: SINT := 0;
	SS_STEP: SINT := 1;
    SS_FIN: SINT := 2;
END_VAR

PROGRAM PLC_PRG
VAR
    In1: LREAL;
	In2: LREAL;
	ssMethodType: SINT := SS_INITIALIZE;
    iter: INT;
    Code: Code;
END_VAR

Code(ssMethodType, In1, In2);


END_PROGRAM


FUNCTION_BLOCK Code
VAR_IN_OUT
	ssMethodType: SINT;
	In1: LREAL;
	In2: LREAL;
END_VAR
VAR_OUTPUT
	y: LREAL;
END_VAR
VAR
	Integrator_DSTATE: LREAL;
	rtb_Sum4: LREAL;
	size: INT;
    cycle: DINT;
END_VAR

CASE ssMethodType OF
    SS_INITIALIZE:
        (* SystemInitialize for Atomic SubSystem: '<Root>/Code 1' *)
        (* InitializeConditions for DiscreteIntegrator: '<S34>/Integrator' *)
		MemSet(ADR(Integrator_DSTATE), 0, size);

        ssMethodType := SS_STEP;

        //Integrator_DSTATE := 0.0;
        (* End of SystemInitialize for SubSystem: '<Root>/Code 1' *)
    SS_STEP:
        cycle := cycle + 1;
        
        IF In1 > 3.14 AND In1 < 3.68 AND In2 < 3.14 AND In2 > 2.5 THEN
            size := size + 1;
        END_IF

        // Dead end
        IF In2 > 0.91 AND In2 < 2.17 THEN
            ssMethodType := SS_FIN;
            RETURN
        END_IF

        // Bug
        IF In1 > 2.0 AND In1 < 3.5 THEN
            ssMethodType := SS_INITIALIZE;
        END_IF

        (* Outputs for Atomic SubSystem: '<Root>/Code 1' *)
        (* Gain: '<S1>/TT - SP Transducer' *)
        rtb_Sum4 := 0.32 * In1;
        (* Saturate: '<S1>/Sat Block (mA)' *)

        IF rtb_Sum4 >= 4.8 THEN
            rtb_Sum4 := 4.8;
        ELSIF rtb_Sum4 <= -11.2 THEN
            rtb_Sum4 := -11.2;
        END_IF;

        (* End of Saturate: '<S1>/Sat Block (mA)' *)


        (* Sum: '<S1>/Sum4' *)
        rtb_Sum4 := rtb_Sum4 - In2;
        (* Outport: '<Root>/y' incorporates:
         *  DiscreteIntegrator: '<S34>/Integrator'
         *  Gain: '<S39>/Proportional Gain'
         *  Sum: '<S43>/Sum' *)
        y := (18.7463 * rtb_Sum4) + Integrator_DSTATE;
        (* Update for DiscreteIntegrator: '<S34>/Integrator' incorporates:
         *  Gain: '<S31>/Integral Gain' *)
        Integrator_DSTATE := ((1.60192 * rtb_Sum4) * 0.05) + Integrator_DSTATE;
        (* End of Outputs for SubSystem: '<Root>/Code 1' *)

    SS_FIN:
        (* Outputs for Atomic SubSystem: '<Root>/Code 1' *)
        (* Gain: '<S1>/TT - SP Transducer' *)
END_CASE;

END_FUNCTION_BLOCK
