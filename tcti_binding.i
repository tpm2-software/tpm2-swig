%module tcti_binding

%{
#include <tss2/tss2_tctildr.h>

%}

%include "tpm2_types.i"

%include "cpointer.i"

%pointer_functions(TSS2_TCTI_CONTEXT *, tcti_ctx_ptr_ptr);

%inline %{

extern TSS2_RC
Tss2_TctiLdr_Initialize_Ex(
    const char *name,
    const char *config,
    TSS2_TCTI_CONTEXT **context);

%}
