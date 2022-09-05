--------------------------- MODULE TimeSync -----------------------------
EXTENDS Integers, TLC

(*--algorithm lamp
variable NETstate = "UNINITED", AMstate = "UNINITED", BMstate = "UNINITED", SENstate = "UNINITED",
  NETtick = 0, AMtick = 0, BMtick = 0, SENtick = 0, StateSet = {"START", "STOP", "UNINITED"};

macro NETtransition(from, to) begin
  either 
      await to = "START";
      NETstate := to
  or
      await to = "STOP";
      NETstate := to
  or
      await to = "EXIT";
      NETstate := to
  or
      await to = "UNINITED";
      NETstate := to
  end either
end macro;

process NETStateMachine = "NET"
begin
  Action:
    either 
        await NETstate = "START";
        NETtick := NETtick + 1;
    or
        await NETstate = "STOP";
    or
        await NETstate = "EXIT";
    or
        await NETstate = "UNINITED";
    end either;
    if NETstate /= "EXIT" then
        goto Action;
    else
        goto EXIT;
    end if;
  EXIT: skip
end process;


process CheckRules = "CheckRules"
begin
  START:
    NETtransition("UNINITED", "START");
  EXIT:
    NETtransition("START", "EXIT");
end process;


end algorithm; *)


\* BEGIN TRANSLATION (chksum(pcal) = "168b3970" /\ chksum(tla) = "110356d3")
\* Label EXIT of process NETStateMachine at line 43 col 9 changed to EXIT_
VARIABLES NETstate, AMstate, BMstate, SENstate, NETtick, AMtick, BMtick, 
          SENtick, StateSet, pc

vars == << NETstate, AMstate, BMstate, SENstate, NETtick, AMtick, BMtick, 
           SENtick, StateSet, pc >>

ProcSet == {"NET"} \cup {"CheckRules"}

Init == (* Global variables *)
        /\ NETstate = "UNINITED"
        /\ AMstate = "UNINITED"
        /\ BMstate = "UNINITED"
        /\ SENstate = "UNINITED"
        /\ NETtick = 0
        /\ AMtick = 0
        /\ BMtick = 0
        /\ SENtick = 0
        /\ StateSet = {"START", "STOP", "UNINITED"}
        /\ pc = [self \in ProcSet |-> CASE self = "NET" -> "Action"
                                        [] self = "CheckRules" -> "START"]

Action == /\ pc["NET"] = "Action"
          /\ \/ /\ NETstate = "START"
                /\ NETtick' = NETtick + 1
                /\ PrintT(NETstate)
             \/ /\ NETstate = "STOP"
                /\ UNCHANGED NETtick
             \/ /\ NETstate = "EXIT"
                /\ UNCHANGED NETtick
             \/ /\ NETstate = "UNINITED"
                /\ UNCHANGED NETtick
          /\ IF NETstate /= "EXIT"
                THEN /\ pc' = [pc EXCEPT !["NET"] = "Action"]
                ELSE /\ pc' = [pc EXCEPT !["NET"] = "EXIT_"]
          /\ UNCHANGED << NETstate, AMstate, BMstate, SENstate, AMtick, BMtick, 
                          SENtick, StateSet >>

EXIT_ == /\ pc["NET"] = "EXIT_"
         /\ TRUE
         /\ pc' = [pc EXCEPT !["NET"] = "Done"]
         /\ UNCHANGED << NETstate, AMstate, BMstate, SENstate, NETtick, AMtick, 
                         BMtick, SENtick, StateSet >>

NETStateMachine == Action \/ EXIT_

START == /\ pc["CheckRules"] = "START"
         /\ \/ /\ "START" = "START"
               /\ NETstate' = "START"
            \/ /\ "START" = "STOP"
               /\ NETstate' = "START"
            \/ /\ "START" = "EXIT"
               /\ NETstate' = "START"
            \/ /\ "START" = "UNINITED"
               /\ NETstate' = "START"
         /\ pc' = [pc EXCEPT !["CheckRules"] = "EXIT"]
         /\ UNCHANGED << AMstate, BMstate, SENstate, NETtick, AMtick, BMtick, 
                         SENtick, StateSet >>

EXIT == /\ pc["CheckRules"] = "EXIT"
        /\ \/ /\ "EXIT" = "START"
              /\ NETstate' = "EXIT"
           \/ /\ "EXIT" = "STOP"
              /\ NETstate' = "EXIT"
           \/ /\ "EXIT" = "EXIT"
              /\ NETstate' = "EXIT"
           \/ /\ "EXIT" = "UNINITED"
              /\ NETstate' = "EXIT"
        /\ pc' = [pc EXCEPT !["CheckRules"] = "Done"]
        /\ UNCHANGED << AMstate, BMstate, SENstate, NETtick, AMtick, BMtick, 
                        SENtick, StateSet >>

CheckRules == START \/ EXIT

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == NETStateMachine \/ CheckRules
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 


==================================================================

