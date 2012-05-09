#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <string.h>
#include "pin.H"


// trace log
FILE * trace;

// state set
set<string> calls;

// handles logging for each call passed to it
VOID RecordCall(VOID * ip, VOID * addr)
{
    char keyedpair[32];
    _snprintf(keyedpair, 18, "%p:%p", ip, addr);

    if (calls.count(keyedpair) == 0)
    {
        fprintf(trace,"%s\n", keyedpair);
        calls.insert(keyedpair);
    }
}

// determines whether or not the instruction is a call
VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsCall(ins))
    {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)RecordCall,
            IARG_INST_PTR,
            IARG_BRANCH_TARGET_ADDR,
            IARG_END);
    }
}

// called before the application exits
VOID Fini(INT32 code, VOID *v)
{
    fclose(trace);
}
 
// print help information
INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of calls and destinations\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

// derp
int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("xrefs_omg.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    
    return 0;
}