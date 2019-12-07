/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *******************************************************************************/

%module esys_binding
%{
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

%}

%include "tpm2_types.i"
%include "mu_binding.i"

%pointer_class(ESYS_TR, ESYS_TR_PTR);
%pointer_functions(ESYS_TR *, ESYS_TR_PTR_PTR);
%pointer_functions(struct ESYS_CONTEXT *, ctx_ptr);
%pointer_functions(struct TSS2_TCTI_CONTEXT *, tcti_ctx_ptr_ptr);

/* The Python Bindings will not work without this. */
%feature("autodoc", "1");

extern TSS2_RC
Tss2_TctiLdr_Initialize_Ex(
    const char *name,
    const char *conf,
    TSS2_TCTI_CONTEXT **context);

extern TSS2_RC
Esys_Initialize(
    ESYS_CONTEXT **esys_context,
    TSS2_TCTI_CONTEXT *tcti,
    TSS2_ABI_VERSION *abiVersion);

extern void
Esys_Finalize(
    ESYS_CONTEXT **context);

extern TSS2_RC
Esys_GetTcti(
    ESYS_CONTEXT *esys_context,
    TSS2_TCTI_CONTEXT **tcti);

extern TSS2_RC
Esys_GetPollHandles(
    ESYS_CONTEXT *esys_context,
    TSS2_TCTI_POLL_HANDLE **handles,
    size_t *count);

extern TSS2_RC
Esys_SetTimeout(
    ESYS_CONTEXT *esys_context,
    int32_t timeout);

extern TSS2_RC
Esys_TR_Serialize(
    ESYS_CONTEXT *esys_context,
    ESYS_TR object,
    uint8_t **buffer,
    size_t *buffer_size);

extern TSS2_RC
Esys_TR_Deserialize(
    ESYS_CONTEXT *esys_context,
    uint8_t const *buffer,
    size_t buffer_size,
    ESYS_TR *esys_handle);

extern TSS2_RC
Esys_TR_FromTPMPublic_Async(
    ESYS_CONTEXT *esysContext,
    TPM2_HANDLE tpm_handle,
    ESYS_TR optionalSession1,
    ESYS_TR optionalSession2,
    ESYS_TR optionalSession3);

extern TSS2_RC
Esys_TR_FromTPMPublic_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *object);

extern TSS2_RC
Esys_TR_FromTPMPublic(
    ESYS_CONTEXT *esysContext,
    TPM2_HANDLE tpm_handle,
    ESYS_TR optionalSession1,
    ESYS_TR optionalSession2,
    ESYS_TR optionalSession3,
    ESYS_TR *object);

extern TSS2_RC
Esys_TR_Close(
    ESYS_CONTEXT *esys_context,
    ESYS_TR *rsrc_handle);

extern TSS2_RC
Esys_TR_SetAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_AUTH const *authValue);

extern TSS2_RC
Esys_TR_GetName(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_NAME **name);

extern TSS2_RC
Esys_TRSess_GetAttributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION *flags);

extern TSS2_RC
Esys_TRSess_SetAttributes(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPMA_SESSION flags,
    TPMA_SESSION mask);

extern TSS2_RC
Esys_TRSess_GetNonceTPM(
    ESYS_CONTEXT *esysContext,
    ESYS_TR session,
    TPM2B_NONCE **nonceTPM);

extern TSS2_RC
Esys_Startup(
    ESYS_CONTEXT *esysContext,
    TPM2_SU startupType);

extern TSS2_RC
Esys_Startup_Async(
    ESYS_CONTEXT *esysContext,
    TPM2_SU startupType);

extern TSS2_RC
Esys_Startup_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_Shutdown(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_SU shutdownType);

extern TSS2_RC
Esys_Shutdown_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_SU shutdownType);

extern TSS2_RC
Esys_Shutdown_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_SelfTest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO fullTest);

extern TSS2_RC
Esys_SelfTest_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO fullTest);

extern TSS2_RC
Esys_SelfTest_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_IncrementalSelfTest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_ALG *toTest,
    TPML_ALG **toDoList);

extern TSS2_RC
Esys_IncrementalSelfTest_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_ALG *toTest);

extern TSS2_RC
Esys_IncrementalSelfTest_Finish(
    ESYS_CONTEXT *esysContext,
    TPML_ALG **toDoList);

extern TSS2_RC
Esys_GetTestResult(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_MAX_BUFFER **outData,
    TPM2_RC *testResult);

extern TSS2_RC
Esys_GetTestResult_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_GetTestResult_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **outData,
    TPM2_RC *testResult);

extern TSS2_RC
Esys_StartAuthSession(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceCaller,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash,
    ESYS_TR *sessionHandle);

extern TSS2_RC
Esys_StartAuthSession_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceCaller,
    TPM2_SE sessionType,
    const TPMT_SYM_DEF *symmetric,
    TPMI_ALG_HASH authHash);

extern TSS2_RC
Esys_StartAuthSession_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *sessionHandle);

extern TSS2_RC
Esys_PolicyRestart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyRestart_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyRestart_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_Create(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

extern TSS2_RC
Esys_Create_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR);

extern TSS2_RC
Esys_Create_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

extern TSS2_RC
Esys_Load(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    ESYS_TR *objectHandle);

extern TSS2_RC
Esys_Load_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inPrivate,
    const TPM2B_PUBLIC *inPublic);

extern TSS2_RC
Esys_Load_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle);

extern TSS2_RC
Esys_LoadExternal(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    TPMI_RH_HIERARCHY hierarchy,
    ESYS_TR *objectHandle);

extern TSS2_RC
Esys_LoadExternal_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE *inPrivate,
    const TPM2B_PUBLIC *inPublic,
    TPMI_RH_HIERARCHY hierarchy);

extern TSS2_RC
Esys_LoadExternal_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle);

extern TSS2_RC
Esys_ReadPublic(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_PUBLIC **outPublic,
    TPM2B_NAME **name,
    TPM2B_NAME **qualifiedName);

extern TSS2_RC
Esys_ReadPublic_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ReadPublic_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PUBLIC **outPublic,
    TPM2B_NAME **name,
    TPM2B_NAME **qualifiedName);

extern TSS2_RC
Esys_ActivateCredential(
    ESYS_CONTEXT *esysContext,
    ESYS_TR activateHandle,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ID_OBJECT *credentialBlob,
    const TPM2B_ENCRYPTED_SECRET *secret,
    TPM2B_DIGEST **certInfo);

extern TSS2_RC
Esys_ActivateCredential_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR activateHandle,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ID_OBJECT *credentialBlob,
    const TPM2B_ENCRYPTED_SECRET *secret);

extern TSS2_RC
Esys_ActivateCredential_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **certInfo);

extern TSS2_RC
Esys_MakeCredential(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *credential,
    const TPM2B_NAME *objectName,
    TPM2B_ID_OBJECT **credentialBlob,
    TPM2B_ENCRYPTED_SECRET **secret);

extern TSS2_RC
Esys_MakeCredential_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *credential,
    const TPM2B_NAME *objectName);

extern TSS2_RC
Esys_MakeCredential_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ID_OBJECT **credentialBlob,
    TPM2B_ENCRYPTED_SECRET **secret);

extern TSS2_RC
Esys_Unseal(
    ESYS_CONTEXT *esysContext,
    ESYS_TR itemHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_SENSITIVE_DATA **outData);

extern TSS2_RC
Esys_Unseal_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR itemHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_Unseal_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_SENSITIVE_DATA **outData);

extern TSS2_RC
Esys_ObjectChangeAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth,
    TPM2B_PRIVATE **outPrivate);

extern TSS2_RC
Esys_ObjectChangeAuth_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

extern TSS2_RC
Esys_ObjectChangeAuth_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outPrivate);

extern TSS2_RC
Esys_CreateLoaded(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_TEMPLATE *inPublic,
    ESYS_TR *objectHandle,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic);

extern TSS2_RC
Esys_CreateLoaded_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_TEMPLATE *inPublic);

extern TSS2_RC
Esys_CreateLoaded_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic);

extern TSS2_RC
Esys_Duplicate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR newParentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_DATA **encryptionKeyOut,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

extern TSS2_RC
Esys_Duplicate_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR newParentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKeyIn,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg);

extern TSS2_RC
Esys_Duplicate_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DATA **encryptionKeyOut,
    TPM2B_PRIVATE **duplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

extern TSS2_RC
Esys_Rewrap(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

extern TSS2_RC
Esys_Rewrap_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR oldParent,
    ESYS_TR newParent,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PRIVATE *inDuplicate,
    const TPM2B_NAME *name,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed);

extern TSS2_RC
Esys_Rewrap_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outDuplicate,
    TPM2B_ENCRYPTED_SECRET **outSymSeed);

extern TSS2_RC
Esys_Import(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKey,
    const TPM2B_PUBLIC *objectPublic,
    const TPM2B_PRIVATE *duplicate,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg,
    TPM2B_PRIVATE **outPrivate);

extern TSS2_RC
Esys_Import_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *encryptionKey,
    const TPM2B_PUBLIC *objectPublic,
    const TPM2B_PRIVATE *duplicate,
    const TPM2B_ENCRYPTED_SECRET *inSymSeed,
    const TPMT_SYM_DEF_OBJECT *symmetricAlg);

extern TSS2_RC
Esys_Import_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PRIVATE **outPrivate);

extern TSS2_RC
Esys_RSA_Encrypt(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *message,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label,
    TPM2B_PUBLIC_KEY_RSA **outData);

extern TSS2_RC
Esys_RSA_Encrypt_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *message,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label);

extern TSS2_RC
Esys_RSA_Encrypt_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PUBLIC_KEY_RSA **outData);

extern TSS2_RC
Esys_RSA_Decrypt(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *cipherText,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label,
    TPM2B_PUBLIC_KEY_RSA **message);

extern TSS2_RC
Esys_RSA_Decrypt_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_PUBLIC_KEY_RSA *cipherText,
    const TPMT_RSA_DECRYPT *inScheme,
    const TPM2B_DATA *label);

extern TSS2_RC
Esys_RSA_Decrypt_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_PUBLIC_KEY_RSA **message);

extern TSS2_RC
Esys_ECDH_KeyGen(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_ECC_POINT **zPoint,
    TPM2B_ECC_POINT **pubPoint);

extern TSS2_RC
Esys_ECDH_KeyGen_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ECDH_KeyGen_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **zPoint,
    TPM2B_ECC_POINT **pubPoint);

extern TSS2_RC
Esys_ECDH_ZGen(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inPoint,
    TPM2B_ECC_POINT **outPoint);

extern TSS2_RC
Esys_ECDH_ZGen_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inPoint);

extern TSS2_RC
Esys_ECDH_ZGen_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **outPoint);

extern TSS2_RC
Esys_ECC_Parameters(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID,
    TPMS_ALGORITHM_DETAIL_ECC **parameters);

extern TSS2_RC
Esys_ECC_Parameters_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID);

extern TSS2_RC
Esys_ECC_Parameters_Finish(
    ESYS_CONTEXT *esysContext,
    TPMS_ALGORITHM_DETAIL_ECC **parameters);

extern TSS2_RC
Esys_ZGen_2Phase(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyA,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inQsB,
    const TPM2B_ECC_POINT *inQeB,
    TPMI_ECC_KEY_EXCHANGE inScheme,
    UINT16 counter,
    TPM2B_ECC_POINT **outZ1,
    TPM2B_ECC_POINT **outZ2);

extern TSS2_RC
Esys_ZGen_2Phase_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyA,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *inQsB,
    const TPM2B_ECC_POINT *inQeB,
    TPMI_ECC_KEY_EXCHANGE inScheme,
    UINT16 counter);

extern TSS2_RC
Esys_ZGen_2Phase_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **outZ1,
    TPM2B_ECC_POINT **outZ2);

extern TSS2_RC
Esys_EncryptDecrypt(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn,
    const TPM2B_MAX_BUFFER *inData,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

extern TSS2_RC
Esys_EncryptDecrypt_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn,
    const TPM2B_MAX_BUFFER *inData);

extern TSS2_RC
Esys_EncryptDecrypt_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

extern TSS2_RC
Esys_EncryptDecrypt2(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *inData,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

extern TSS2_RC
Esys_EncryptDecrypt2_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *inData,
    TPMI_YES_NO decrypt,
    TPMI_ALG_SYM_MODE mode,
    const TPM2B_IV *ivIn);

extern TSS2_RC
Esys_EncryptDecrypt2_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **outData,
    TPM2B_IV **ivOut);

extern TSS2_RC
Esys_Hash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **outHash,
    TPMT_TK_HASHCHECK **validation);

extern TSS2_RC
Esys_Hash_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *data,
    TPMI_ALG_HASH hashAlg,
    TPMI_RH_HIERARCHY hierarchy);

extern TSS2_RC
Esys_Hash_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **outHash,
    TPMT_TK_HASHCHECK **validation);

extern TSS2_RC
Esys_HMAC(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_ALG_HASH hashAlg,
    TPM2B_DIGEST **outHMAC);

extern TSS2_RC
Esys_HMAC_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_ALG_HASH hashAlg);

extern TSS2_RC
Esys_HMAC_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **outHMAC);

extern TSS2_RC
Esys_GetRandom(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 bytesRequested,
    TPM2B_DIGEST **randomBytes);

extern TSS2_RC
Esys_GetRandom_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 bytesRequested);

extern TSS2_RC
Esys_GetRandom_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **randomBytes);

extern TSS2_RC
Esys_StirRandom(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_DATA *inData);

extern TSS2_RC
Esys_StirRandom_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_DATA *inData);

extern TSS2_RC
Esys_StirRandom_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_HMAC_Start(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg,
    ESYS_TR *sequenceHandle);

extern TSS2_RC
Esys_HMAC_Start_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg);

extern TSS2_RC
Esys_HMAC_Start_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *sequenceHandle);

extern TSS2_RC
Esys_HashSequenceStart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg,
    ESYS_TR *sequenceHandle);

extern TSS2_RC
Esys_HashSequenceStart_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    TPMI_ALG_HASH hashAlg);

extern TSS2_RC
Esys_HashSequenceStart_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *sequenceHandle);

extern TSS2_RC
Esys_SequenceUpdate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

extern TSS2_RC
Esys_SequenceUpdate_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

extern TSS2_RC
Esys_SequenceUpdate_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_SequenceComplete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_RH_HIERARCHY hierarchy,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation);

extern TSS2_RC
Esys_SequenceComplete_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPMI_RH_HIERARCHY hierarchy);

extern TSS2_RC
Esys_SequenceComplete_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **result,
    TPMT_TK_HASHCHECK **validation);

extern TSS2_RC
Esys_EventSequenceComplete(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer,
    TPML_DIGEST_VALUES **results);

extern TSS2_RC
Esys_EventSequenceComplete_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR sequenceHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *buffer);

extern TSS2_RC
Esys_EventSequenceComplete_Finish(
    ESYS_CONTEXT *esysContext,
    TPML_DIGEST_VALUES **results);

extern TSS2_RC
Esys_Certify(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_Certify_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR objectHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

extern TSS2_RC
Esys_Certify_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_CertifyCreation(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_CertifyCreation_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPM2B_DIGEST *creationHash,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_CREATION *creationTicket);

extern TSS2_RC
Esys_CertifyCreation_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_Quote(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    const TPML_PCR_SELECTION *PCRselect,
    TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_Quote_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    const TPML_PCR_SELECTION *PCRselect);

extern TSS2_RC
Esys_Quote_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **quoted,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_GetSessionAuditDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_GetSessionAuditDigest_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR sessionHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

extern TSS2_RC
Esys_GetSessionAuditDigest_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_GetCommandAuditDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_GetCommandAuditDigest_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

extern TSS2_RC
Esys_GetCommandAuditDigest_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **auditInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_GetTime(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    TPM2B_ATTEST **timeInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_GetTime_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR privacyAdminHandle,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme);

extern TSS2_RC
Esys_GetTime_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **timeInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_Commit(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2,
    TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L,
    TPM2B_ECC_POINT **E,
    UINT16 *counter);

extern TSS2_RC
Esys_Commit_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_ECC_POINT *P1,
    const TPM2B_SENSITIVE_DATA *s2,
    const TPM2B_ECC_PARAMETER *y2);

extern TSS2_RC
Esys_Commit_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L,
    TPM2B_ECC_POINT **E,
    UINT16 *counter);

extern TSS2_RC
Esys_EC_Ephemeral(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID,
    TPM2B_ECC_POINT **Q,
    UINT16 *counter);

extern TSS2_RC
Esys_EC_Ephemeral_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ECC_CURVE curveID);

extern TSS2_RC
Esys_EC_Ephemeral_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ECC_POINT **Q,
    UINT16 *counter);

extern TSS2_RC
Esys_VerifySignature(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIGNATURE *signature,
    TPMT_TK_VERIFIED **validation);

extern TSS2_RC
Esys_VerifySignature_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIGNATURE *signature);

extern TSS2_RC
Esys_VerifySignature_Finish(
    ESYS_CONTEXT *esysContext,
    TPMT_TK_VERIFIED **validation);

extern TSS2_RC
Esys_Sign(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_HASHCHECK *validation,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_Sign_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *digest,
    const TPMT_SIG_SCHEME *inScheme,
    const TPMT_TK_HASHCHECK *validation);

extern TSS2_RC
Esys_Sign_Finish(
    ESYS_CONTEXT *esysContext,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_SetCommandCodeAuditStatus(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ALG_HASH auditAlg,
    const TPML_CC *setList,
    const TPML_CC *clearList);

extern TSS2_RC
Esys_SetCommandCodeAuditStatus_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_ALG_HASH auditAlg,
    const TPML_CC *setList,
    const TPML_CC *clearList);

extern TSS2_RC
Esys_SetCommandCodeAuditStatus_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PCR_Extend(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST_VALUES *digests);

extern TSS2_RC
Esys_PCR_Extend_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST_VALUES *digests);

extern TSS2_RC
Esys_PCR_Extend_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PCR_Event(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_EVENT *eventData,
    TPML_DIGEST_VALUES **digests);

extern TSS2_RC
Esys_PCR_Event_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_EVENT *eventData);

extern TSS2_RC
Esys_PCR_Event_Finish(
    ESYS_CONTEXT *esysContext,
    TPML_DIGEST_VALUES **digests);

extern TSS2_RC
Esys_PCR_Read(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrSelectionIn,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION **pcrSelectionOut,
    TPML_DIGEST **pcrValues);

extern TSS2_RC
Esys_PCR_Read_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrSelectionIn);

extern TSS2_RC
Esys_PCR_Read_Finish(
    ESYS_CONTEXT *esysContext,
    UINT32 *pcrUpdateCounter,
    TPML_PCR_SELECTION **pcrSelectionOut,
    TPML_DIGEST **pcrValues);

extern TSS2_RC
Esys_PCR_Allocate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrAllocation,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable);

extern TSS2_RC
Esys_PCR_Allocate_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_PCR_SELECTION *pcrAllocation);

extern TSS2_RC
Esys_PCR_Allocate_Finish(
    ESYS_CONTEXT *esysContext,
    TPMI_YES_NO *allocationSuccess,
    UINT32 *maxPCR,
    UINT32 *sizeNeeded,
    UINT32 *sizeAvailable);

extern TSS2_RC
Esys_PCR_SetAuthPolicy(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg,
    TPMI_DH_PCR pcrNum);

extern TSS2_RC
Esys_PCR_SetAuthPolicy_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg,
    TPMI_DH_PCR pcrNum);

extern TSS2_RC
Esys_PCR_SetAuthPolicy_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PCR_SetAuthValue(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *auth);

extern TSS2_RC
Esys_PCR_SetAuthValue_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *auth);

extern TSS2_RC
Esys_PCR_SetAuthValue_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PCR_Reset(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PCR_Reset_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR pcrHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PCR_Reset_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicySigned(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authObject,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    const TPMT_SIGNATURE *auth,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

extern TSS2_RC
Esys_PolicySigned_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authObject,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    const TPMT_SIGNATURE *auth);

extern TSS2_RC
Esys_PolicySigned_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

extern TSS2_RC
Esys_PolicySecret(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

extern TSS2_RC
Esys_PolicySecret_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NONCE *nonceTPM,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    INT32 expiration);

extern TSS2_RC
Esys_PolicySecret_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_TIMEOUT **timeout,
    TPMT_TK_AUTH **policyTicket);

extern TSS2_RC
Esys_PolicyTicket(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_TIMEOUT *timeout,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *authName,
    const TPMT_TK_AUTH *ticket);

extern TSS2_RC
Esys_PolicyTicket_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_TIMEOUT *timeout,
    const TPM2B_DIGEST *cpHashA,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *authName,
    const TPMT_TK_AUTH *ticket);

extern TSS2_RC
Esys_PolicyTicket_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyOR(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST *pHashList);

extern TSS2_RC
Esys_PolicyOR_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_DIGEST *pHashList);

extern TSS2_RC
Esys_PolicyOR_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyPCR(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs);

extern TSS2_RC
Esys_PolicyPCR_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *pcrDigest,
    const TPML_PCR_SELECTION *pcrs);

extern TSS2_RC
Esys_PolicyPCR_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyLocality(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMA_LOCALITY locality);

extern TSS2_RC
Esys_PolicyLocality_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMA_LOCALITY locality);

extern TSS2_RC
Esys_PolicyLocality_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyNV(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

extern TSS2_RC
Esys_PolicyNV_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

extern TSS2_RC
Esys_PolicyNV_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyCounterTimer(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

extern TSS2_RC
Esys_PolicyCounterTimer_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_OPERAND *operandB,
    UINT16 offset,
    TPM2_EO operation);

extern TSS2_RC
Esys_PolicyCounterTimer_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyCommandCode(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code);

extern TSS2_RC
Esys_PolicyCommandCode_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CC code);

extern TSS2_RC
Esys_PolicyCommandCode_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyPhysicalPresence(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyPhysicalPresence_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyPhysicalPresence_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyCpHash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *cpHashA);

extern TSS2_RC
Esys_PolicyCpHash_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *cpHashA);

extern TSS2_RC
Esys_PolicyCpHash_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyNameHash(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *nameHash);

extern TSS2_RC
Esys_PolicyNameHash_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *nameHash);

extern TSS2_RC
Esys_PolicyNameHash_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyDuplicationSelect(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NAME *objectName,
    const TPM2B_NAME *newParentName,
    TPMI_YES_NO includeObject);

extern TSS2_RC
Esys_PolicyDuplicationSelect_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_NAME *objectName,
    const TPM2B_NAME *newParentName,
    TPMI_YES_NO includeObject);

extern TSS2_RC
Esys_PolicyDuplicationSelect_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyAuthorize(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *approvedPolicy,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *keySign,
    const TPMT_TK_VERIFIED *checkTicket);

extern TSS2_RC
Esys_PolicyAuthorize_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *approvedPolicy,
    const TPM2B_NONCE *policyRef,
    const TPM2B_NAME *keySign,
    const TPMT_TK_VERIFIED *checkTicket);

extern TSS2_RC
Esys_PolicyAuthorize_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyAuthValue(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyAuthValue_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyAuthValue_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyPassword(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyPassword_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyPassword_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyGetDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST **policyDigest);

extern TSS2_RC
Esys_PolicyGetDigest_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyGetDigest_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DIGEST **policyDigest);

extern TSS2_RC
Esys_PolicyNvWritten(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO writtenSet);

extern TSS2_RC
Esys_PolicyNvWritten_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO writtenSet);

extern TSS2_RC
Esys_PolicyNvWritten_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyTemplate(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *templateHash);

extern TSS2_RC
Esys_PolicyTemplate_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *templateHash);

extern TSS2_RC
Esys_PolicyTemplate_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PolicyAuthorizeNV(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyAuthorizeNV_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_PolicyAuthorizeNV_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_CreatePrimary(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

extern TSS2_RC
Esys_CreatePrimary_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_SENSITIVE_CREATE *inSensitive,
    const TPM2B_PUBLIC *inPublic,
    const TPM2B_DATA *outsideInfo,
    const TPML_PCR_SELECTION *creationPCR);

extern TSS2_RC
Esys_CreatePrimary_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPMT_TK_CREATION **creationTicket);

extern TSS2_RC
Esys_HierarchyControl(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_RH_ENABLES enable,
    TPMI_YES_NO state);

extern TSS2_RC
Esys_HierarchyControl_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_RH_ENABLES enable,
    TPMI_YES_NO state);

extern TSS2_RC
Esys_HierarchyControl_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_SetPrimaryPolicy(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg);

extern TSS2_RC
Esys_SetPrimaryPolicy_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *authPolicy,
    TPMI_ALG_HASH hashAlg);

extern TSS2_RC
Esys_SetPrimaryPolicy_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_ChangePPS(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ChangePPS_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ChangePPS_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_ChangeEPS(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ChangeEPS_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ChangeEPS_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_Clear(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_Clear_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_Clear_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_ClearControl(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO disable);

extern TSS2_RC
Esys_ClearControl_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_YES_NO disable);

extern TSS2_RC
Esys_ClearControl_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_HierarchyChangeAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

extern TSS2_RC
Esys_HierarchyChangeAuth_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

extern TSS2_RC
Esys_HierarchyChangeAuth_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_DictionaryAttackLockReset(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_DictionaryAttackLockReset_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_DictionaryAttackLockReset_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_DictionaryAttackParameters(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery);

extern TSS2_RC
Esys_DictionaryAttackParameters_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery);

extern TSS2_RC
Esys_DictionaryAttackParameters_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_PP_Commands(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_CC *setList,
    const TPML_CC *clearList);

extern TSS2_RC
Esys_PP_Commands_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPML_CC *setList,
    const TPML_CC *clearList);

extern TSS2_RC
Esys_PP_Commands_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_SetAlgorithmSet(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 algorithmSet);

extern TSS2_RC
Esys_SetAlgorithmSet_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 algorithmSet);

extern TSS2_RC
Esys_SetAlgorithmSet_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_FieldUpgradeStart(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authorization,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *fuDigest,
    const TPMT_SIGNATURE *manifestSignature);

extern TSS2_RC
Esys_FieldUpgradeStart_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authorization,
    ESYS_TR keyHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DIGEST *fuDigest,
    const TPMT_SIGNATURE *manifestSignature);

extern TSS2_RC
Esys_FieldUpgradeStart_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_FieldUpgradeData(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *fuData,
    TPMT_HA **nextDigest,
    TPMT_HA **firstDigest);

extern TSS2_RC
Esys_FieldUpgradeData_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_BUFFER *fuData);

extern TSS2_RC
Esys_FieldUpgradeData_Finish(
    ESYS_CONTEXT *esysContext,
    TPMT_HA **nextDigest,
    TPMT_HA **firstDigest);

extern TSS2_RC
Esys_FirmwareRead(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 sequenceNumber,
    TPM2B_MAX_BUFFER **fuData);

extern TSS2_RC
Esys_FirmwareRead_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 sequenceNumber);

extern TSS2_RC
Esys_FirmwareRead_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_BUFFER **fuData);

extern TSS2_RC
Esys_ContextSave(
    ESYS_CONTEXT *esysContext,
    ESYS_TR saveHandle,
    TPMS_CONTEXT **context);

extern TSS2_RC
Esys_ContextSave_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR saveHandle);

extern TSS2_RC
Esys_ContextSave_Finish(
    ESYS_CONTEXT *esysContext,
    TPMS_CONTEXT **context);

extern TSS2_RC
Esys_ContextLoad(
    ESYS_CONTEXT *esysContext,
    const TPMS_CONTEXT *context,
    ESYS_TR *loadedHandle);

extern TSS2_RC
Esys_ContextLoad_Async(
    ESYS_CONTEXT *esysContext,
    const TPMS_CONTEXT *context);

extern TSS2_RC
Esys_ContextLoad_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *loadedHandle);

extern TSS2_RC
Esys_FlushContext(
    ESYS_CONTEXT *esysContext,
    ESYS_TR flushHandle);

extern TSS2_RC
Esys_FlushContext_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR flushHandle);

extern TSS2_RC
Esys_FlushContext_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_EvictControl(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_DH_PERSISTENT persistentHandle,
    ESYS_TR *newObjectHandle);

extern TSS2_RC
Esys_EvictControl_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR objectHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMI_DH_PERSISTENT persistentHandle);

extern TSS2_RC
Esys_EvictControl_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *newObjectHandle);

extern TSS2_RC
Esys_ReadClock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPMS_TIME_INFO **currentTime);

extern TSS2_RC
Esys_ReadClock_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_ReadClock_Finish(
    ESYS_CONTEXT *esysContext,
    TPMS_TIME_INFO **currentTime);

extern TSS2_RC
Esys_ClockSet(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 newTime);

extern TSS2_RC
Esys_ClockSet_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 newTime);

extern TSS2_RC
Esys_ClockSet_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_ClockRateAdjust(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CLOCK_ADJUST rateAdjust);

extern TSS2_RC
Esys_ClockRateAdjust_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR auth,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CLOCK_ADJUST rateAdjust);

extern TSS2_RC
Esys_ClockRateAdjust_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_GetCapability(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CAP capability,
    UINT32 property,
    UINT32 propertyCount,
    TPMI_YES_NO *moreData,
    TPMS_CAPABILITY_DATA **capabilityData);

extern TSS2_RC
Esys_GetCapability_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2_CAP capability,
    UINT32 property,
    UINT32 propertyCount);

extern TSS2_RC
Esys_GetCapability_Finish(
    ESYS_CONTEXT *esysContext,
    TPMI_YES_NO *moreData,
    TPMS_CAPABILITY_DATA **capabilityData);

extern TSS2_RC
Esys_TestParms(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPMT_PUBLIC_PARMS *parameters);

extern TSS2_RC
Esys_TestParms_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPMT_PUBLIC_PARMS *parameters);

extern TSS2_RC
Esys_TestParms_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_DefineSpace(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    const TPM2B_NV_PUBLIC *publicInfo,
    ESYS_TR *nvHandle);

extern TSS2_RC
Esys_NV_DefineSpace_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *auth,
    const TPM2B_NV_PUBLIC *publicInfo);

extern TSS2_RC
Esys_NV_DefineSpace_Finish(
    ESYS_CONTEXT *esysContext,
    ESYS_TR *nvHandle);

extern TSS2_RC
Esys_NV_UndefineSpace(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_UndefineSpace_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_UndefineSpace_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_UndefineSpaceSpecial(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR platform,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_UndefineSpaceSpecial_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR platform,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_UndefineSpaceSpecial_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_ReadPublic(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_NV_PUBLIC **nvPublic,
    TPM2B_NAME **nvName);

extern TSS2_RC
Esys_NV_ReadPublic_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_ReadPublic_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_NV_PUBLIC **nvPublic,
    TPM2B_NAME **nvName);

extern TSS2_RC
Esys_NV_Write(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset);

extern TSS2_RC
Esys_NV_Write_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data,
    UINT16 offset);

extern TSS2_RC
Esys_NV_Write_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_Increment(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_Increment_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_Increment_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_Extend(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data);

extern TSS2_RC
Esys_NV_Extend_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_MAX_NV_BUFFER *data);

extern TSS2_RC
Esys_NV_Extend_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_SetBits(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 bits);

extern TSS2_RC
Esys_NV_SetBits_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT64 bits);

extern TSS2_RC
Esys_NV_SetBits_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_WriteLock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_WriteLock_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_WriteLock_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_GlobalWriteLock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_GlobalWriteLock_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_GlobalWriteLock_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_Read(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 size,
    UINT16 offset,
    TPM2B_MAX_NV_BUFFER **data);

extern TSS2_RC
Esys_NV_Read_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT16 size,
    UINT16 offset);

extern TSS2_RC
Esys_NV_Read_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_MAX_NV_BUFFER **data);

extern TSS2_RC
Esys_NV_ReadLock(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_ReadLock_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

extern TSS2_RC
Esys_NV_ReadLock_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_ChangeAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

extern TSS2_RC
Esys_NV_ChangeAuth_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_AUTH *newAuth);

extern TSS2_RC
Esys_NV_ChangeAuth_Finish(
    ESYS_CONTEXT *esysContext);

extern TSS2_RC
Esys_NV_Certify(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_NV_Certify_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR signHandle,
    ESYS_TR authHandle,
    ESYS_TR nvIndex,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *qualifyingData,
    const TPMT_SIG_SCHEME *inScheme,
    UINT16 size,
    UINT16 offset);

extern TSS2_RC
Esys_NV_Certify_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_ATTEST **certifyInfo,
    TPMT_SIGNATURE **signature);

extern TSS2_RC
Esys_Vendor_TCG_Test(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *inputData,
    TPM2B_DATA **outputData);

extern TSS2_RC
Esys_Vendor_TCG_Test_Async(
    ESYS_CONTEXT *esysContext,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    const TPM2B_DATA *inputData);

extern TSS2_RC
Esys_Vendor_TCG_Test_Finish(
    ESYS_CONTEXT *esysContext,
    TPM2B_DATA **outputData);

extern void
Esys_Free(void *ptr);
