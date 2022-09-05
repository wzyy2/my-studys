--------------------------- MODULE TimeSync -----------------------------
EXTENDS Naturals, TLC

(*--algorithm lamp
variable NETstate = "UNINITED", AMstate = "UNINITED", BMstate = "UNINITED", SENstate = "UNINITED",
  NETtick = 0, AMtick = 0, BMtick = 0, SENtick = 0,
  ACTIVEmachine = 0;

macro NETtransition(from, to) begin
  either 
      await to = "START";
      NETstate := to
  or
      await to = "STOP";
      NETstate := to
  or
      await to = "INVAILD";
      NETstate := to
  or
      await to = "UNINITED";
      NETstate := to
  end either;
end macro;

macro AMtransition(from, to) begin
  either 
      await to = "START";
      with NETstate = "START" do
          AMtick := NETtick;
          AMstate := to;
      end with;

      if ACTIVEmachine = 0 then ACTIVEmachine := 1; end if;
  or
      await to = "STOP";
      AMstate := to
  or
      await to = "INVAILD";
      AMstate := to
  or
      await to = "UNINITED";
      AMstate := to
  end either;
end macro;

macro BMtransition(from ,to) begin
  either 
      await to = "START";
      with AMstate = "START" do
          BMtick := AMtick;
          BMstate := to;
      end with;
  or
      await to = "STOP";
      BMstate := to;
  or
      await to = "INVAILD";
      BMstate := to;
  or
      await to = "UNINITED";
      BMstate := to;
  end either;
end macro;

macro SENtransition(from , to) begin
  either 
      await to = "START";
      with AMstate = "START" do
          SENtick := AMtick;
          SENstate := to;
      end with;
  or
      await to = "STOP";
      BMstate := to;
  or
      await to = "INVAILD";
      BMstate := to;
  or
      await to = "UNINITED";
      BMstate := to;
  end either;
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
        await NETstate = "INVAILD";
    or
        await NETstate = "UNINITED";
    end either;
    goto Action;
end process;

process AMStateMachine = "AM"
begin
  Action:
    either 
        await AMstate = "START";
        AMtick := AMtick + 2;
      or
        await AMstate = "STOP";
    or
        await AMstate = "INVAILD";
    or
        await AMstate = "UNINITED";
    end either;
    goto Action;
end process;

process BMStateMachine = "BM"
begin
  Action:
    either 
        await BMstate = "START";
        BMtick := BMtick + 3;
      or
        await BMstate = "STOP";
    or
        await BMstate = "INVAILD";
    or
        await BMstate = "UNINITED";
    end either;
    goto Action;
end process;

process SENStateMachine = "SEN"
begin
  Action:
    either 
        await SENstate = "START";
        SENtick := SENtick + 4;
      or
        await SENstate = "STOP";
    or
        await SENstate = "INVAILD";
    or
        await SENstate = "UNINITED";
    end either;
    goto Action;
end process;


end algorithm; *)


\* BEGIN TRANSLATION (chksum(pcal) = "340a404b" /\ chksum(tla) = "12ed7c28")
\* Label Action of process NETStateMachine at line 87 col 5 changed to Action_
\* Label Action of process AMStateMachine at line 103 col 5 changed to Action_A
\* Label Action of process BMStateMachine at line 119 col 5 changed to Action_B
VARIABLES NETstate, AMstate, BMstate, SENstate, NETtick, AMtick, BMtick, 
          SENtick, ACTIVEmachine, pc

vars == << NETstate, AMstate, BMstate, SENstate, NETtick, AMtick, BMtick, 
           SENtick, ACTIVEmachine, pc >>

ProcSet == {"NET"} \cup {"AM"} \cup {"BM"} \cup {"SEN"}

Init == (* Global variables *)
        /\ NETstate = "UNINITED"
        /\ AMstate = "UNINITED"
        /\ BMstate = "UNINITED"
        /\ SENstate = "UNINITED"
        /\ NETtick = 0
        /\ AMtick = 0
        /\ BMtick = 0
        /\ SENtick = 0
        /\ ACTIVEmachine = 0
        /\ pc = [self \in ProcSet |-> CASE self = "NET" -> "Action_"
                                        [] self = "AM" -> "Action_A"
                                        [] self = "BM" -> "Action_B"
                                        [] self = "SEN" -> "Action"]

Action_ == /\ pc["NET"] = "Action_"
           /\ \/ /\ NETstate = "START"
                 /\ NETtick' = NETtick + 1
              \/ /\ NETstate = "STOP"
                 /\ UNCHANGED NETtick
              \/ /\ NETstate = "INVAILD"
                 /\ UNCHANGED NETtick
              \/ /\ NETstate = "UNINITED"
                 /\ UNCHANGED NETtick
           /\ pc' = [pc EXCEPT !["NET"] = "Action_"]
           /\ UNCHANGED << NETstate, AMstate, BMstate, SENstate, AMtick, 
                           BMtick, SENtick, ACTIVEmachine >>

NETStateMachine == Action_

Action_A == /\ pc["AM"] = "Action_A"
            /\ \/ /\ AMstate = "START"
                  /\ AMtick' = AMtick + 2
               \/ /\ AMstate = "STOP"
                  /\ UNCHANGED AMtick
               \/ /\ AMstate = "INVAILD"
                  /\ UNCHANGED AMtick
               \/ /\ AMstate = "UNINITED"
                  /\ UNCHANGED AMtick
            /\ pc' = [pc EXCEPT !["AM"] = "Action_A"]
            /\ UNCHANGED << NETstate, AMstate, BMstate, SENstate, NETtick, 
                            BMtick, SENtick, ACTIVEmachine >>

AMStateMachine == Action_A

Action_B == /\ pc["BM"] = "Action_B"
            /\ \/ /\ BMstate = "START"
                  /\ BMtick' = BMtick + 3
               \/ /\ BMstate = "STOP"
                  /\ UNCHANGED BMtick
               \/ /\ BMstate = "INVAILD"
                  /\ UNCHANGED BMtick
               \/ /\ BMstate = "UNINITED"
                  /\ UNCHANGED BMtick
            /\ pc' = [pc EXCEPT !["BM"] = "Action_B"]
            /\ UNCHANGED << NETstate, AMstate, BMstate, SENstate, NETtick, 
                            AMtick, SENtick, ACTIVEmachine >>

BMStateMachine == Action_B

Action == /\ pc["SEN"] = "Action"
          /\ \/ /\ SENstate = "START"
                /\ SENtick' = SENtick + 4
             \/ /\ SENstate = "STOP"
                /\ UNCHANGED SENtick
             \/ /\ SENstate = "INVAILD"
                /\ UNCHANGED SENtick
             \/ /\ SENstate = "UNINITED"
                /\ UNCHANGED SENtick
          /\ pc' = [pc EXCEPT !["SEN"] = "Action"]
          /\ UNCHANGED << NETstate, AMstate, BMstate, SENstate, NETtick, 
                          AMtick, BMtick, ACTIVEmachine >>

SENStateMachine == Action

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == NETStateMachine \/ AMStateMachine \/ BMStateMachine
           \/ SENStateMachine
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION 


==================================================================

