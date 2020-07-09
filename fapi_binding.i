/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *******************************************************************************/

%module fapi_binding
%{
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

%}

%include "tpm2_types.i"
%include "mu_binding.i"

%pointer_functions(struct FAPI_CONTEXT *, fapi_ctx_ptr);

%sizeof(FAPI_POLL_HANDLE);
%array_class(FAPI_POLL_HANDLE, FAPI_POLL_HANDLE_ARRAY);
%pointer_functions(FAPI_POLL_HANDLE, FAPI_POLL_HANDLE_PTR);
%pointer_functions(FAPI_POLL_HANDLE *, FAPI_POLL_HANDLE_PTR_PTR);

/* The Python Bindings will not work without this. */
%feature("autodoc", "1");

/* Type definitions */
typedef struct FAPI_CONTEXT FAPI_CONTEXT;

/* Context functions */

extern TSS2_RC Fapi_Initialize(
    FAPI_CONTEXT  **context,
    char     const *uri);

extern TSS2_RC Fapi_Initialize_Async(
    FAPI_CONTEXT  **context,
    char     const *uri);

extern TSS2_RC Fapi_Initialize_Finish(
    FAPI_CONTEXT  **context);

extern void Fapi_Finalize(
    FAPI_CONTEXT  **context);

extern TSS2_RC Fapi_GetTcti(
    FAPI_CONTEXT       *context,
    TSS2_TCTI_CONTEXT **tcti);

extern void Fapi_Free(
    void           *ptr);

extern TSS2_RC Fapi_GetPollHandles(
    FAPI_CONTEXT      *context,
    FAPI_POLL_HANDLE **handles,
    size_t            *num_handles);

extern TSS2_RC Fapi_GetInfo(
    FAPI_CONTEXT   *context,
    char          **info);

extern TSS2_RC Fapi_GetInfo_Async(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_GetInfo_Finish(
    FAPI_CONTEXT   *context,
    char          **info);

/* General functions */

extern TSS2_RC Fapi_Provision(
    FAPI_CONTEXT   *context,
    char     const *authValueEh,
    char     const *authValueSh,
    char     const *authValueLockout);

extern TSS2_RC Fapi_Provision_Async(
    FAPI_CONTEXT   *context,
    char     const *authValueEh,
    char     const *authValueSh,
    char     const *authValueLockout);

extern TSS2_RC Fapi_Provision_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_GetPlatformCertificates(
    FAPI_CONTEXT   *context,
    uint8_t       **certificates,
    size_t         *certificatesSize);

extern TSS2_RC Fapi_GetPlatformCertificates_Async(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_GetPlatformCertificates_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **certificates,
    size_t         *certificatesSize);

extern TSS2_RC Fapi_GetRandom(
    FAPI_CONTEXT   *context,
    size_t          numBytes,
    uint8_t       **data);

extern TSS2_RC Fapi_GetRandom_Async(
    FAPI_CONTEXT   *context,
    size_t          numBytes);

extern TSS2_RC Fapi_GetRandom_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **data);

extern TSS2_RC Fapi_Import(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *importData);

extern TSS2_RC Fapi_Import_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *importData);

extern TSS2_RC Fapi_Import_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_List(
    FAPI_CONTEXT   *context,
    char     const *searchPath,
    char          **pathList);

extern TSS2_RC Fapi_List_Async(
    FAPI_CONTEXT   *context,
    char     const *searchPath);

extern TSS2_RC Fapi_List_Finish(
    FAPI_CONTEXT   *context,
    char          **pathList);

extern TSS2_RC Fapi_Delete(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_Delete_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_Delete_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_ChangeAuth(
    FAPI_CONTEXT   *context,
    char     const *entityPath,
    char     const *authValue);

extern TSS2_RC Fapi_ChangeAuth_Async(
    FAPI_CONTEXT   *context,
    char     const *entityPath,
    char     const *authValue);

extern TSS2_RC Fapi_ChangeAuth_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_SetDescription(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *description);

extern TSS2_RC Fapi_SetDescription_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *description);

extern TSS2_RC Fapi_SetDescription_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_GetDescription(
    FAPI_CONTEXT   *context,
    char     const *path,
    char          **description);

extern TSS2_RC Fapi_GetDescription_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_GetDescription_Finish(
    FAPI_CONTEXT   *context,
    char          **description);

extern TSS2_RC Fapi_SetAppData(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint8_t  const *appData,
    size_t          appDataSize);

extern TSS2_RC Fapi_SetAppData_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint8_t  const *appData,
    size_t          appDataSize);

extern TSS2_RC Fapi_SetAppData_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_GetAppData(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint8_t       **appData,
    size_t         *appDataSize);

extern TSS2_RC Fapi_GetAppData_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_GetAppData_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **appData,
    size_t         *appDataSize);

extern TSS2_RC Fapi_GetTpmBlobs(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint8_t       **tpm2bPublic,
    size_t         *tpm2bPublicSize,
    uint8_t       **tpm2bPrivate,
    size_t         *tpm2bPrivateSize,
    char          **policy);

extern TSS2_RC Fapi_GetTpmBlobs_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_GetTpmBlobs_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **tpm2bPublic,
    size_t         *tpm2bPublicSize,
    uint8_t       **tpm2bPrivate,
    size_t         *tpm2bPrivateSize,
    char          **policy);

/* Key functions */

extern TSS2_RC Fapi_CreateKey(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *type,
    char     const *policyPath,
    char     const *authValue);

extern TSS2_RC Fapi_CreateKey_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *type,
    char     const *policyPath,
    char     const *authValue);

extern TSS2_RC Fapi_CreateKey_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_Sign(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    char     const *padding,
    uint8_t  const *digest,
    size_t          digestSize,
    uint8_t       **signature,
    size_t         *signatureSize,
    char          **publicKey,
    char          **certificate);

extern TSS2_RC Fapi_Sign_Async(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    char     const *padding,
    uint8_t  const *digest,
    size_t         digestSize);

extern TSS2_RC Fapi_Sign_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **signature,
    size_t         *signatureSize,
    char          **publicKey,
    char          **certificate);

extern TSS2_RC Fapi_VerifySignature(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    uint8_t  const *digest,
    size_t          digestSize,
    uint8_t  const *signature,
    size_t          signatureSize);

extern TSS2_RC Fapi_VerifySignature_Async(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    uint8_t  const *digest,
    size_t          digestSize,
    uint8_t  const *signature,
    size_t          signatureSize);

extern TSS2_RC Fapi_VerifySignature_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_Encrypt(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    uint8_t  const *plainText,
    size_t          plainTextSize,
    uint8_t       **cipherText,
    size_t         *cipherTextSize);

extern TSS2_RC Fapi_Encrypt_Async(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    uint8_t  const *plainText,
    size_t          plainTextSize);

extern TSS2_RC Fapi_Encrypt_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **cipherText,
    size_t         *cipherTextSize );

extern TSS2_RC Fapi_Decrypt(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    uint8_t  const *cipherText,
    size_t          cipherTextSize,
    uint8_t       **plainText,
    size_t         *plainTextSize);

extern TSS2_RC Fapi_Decrypt_Async(
    FAPI_CONTEXT   *context,
    char     const *keyPath,
    uint8_t  const *cipherText,
    size_t          cipherTextSize);

extern TSS2_RC Fapi_Decrypt_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **plainText,
    size_t         *plainTextSize);

extern TSS2_RC Fapi_SetCertificate(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *x509certData);

extern TSS2_RC Fapi_SetCertificate_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *x509certData);

extern TSS2_RC Fapi_SetCertificate_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_GetCertificate(
    FAPI_CONTEXT   *context,
    char     const *path,
    char          **x509certData);

extern TSS2_RC Fapi_GetCertificate_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_GetCertificate_Finish(
    FAPI_CONTEXT   *context,
    char          **x509certData);

extern TSS2_RC Fapi_ExportKey(
    FAPI_CONTEXT   *context,
    char     const *pathOfKeyToDuplicate,
    char     const *pathToPublicKeyOfNewParent,
    char          **exportedData);

extern TSS2_RC Fapi_ExportKey_Async(
    FAPI_CONTEXT   *context,
    char     const *pathOfKeyToDuplicate,
    char     const *pathToPublicKeyOfNewParent);

extern TSS2_RC Fapi_ExportKey_Finish(
    FAPI_CONTEXT   *context,
    char          **exportedData);

/* Seal functions */

extern TSS2_RC Fapi_CreateSeal(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *type,
    size_t          size,
    char     const *policyPath,
    char     const *authValue,
    uint8_t  const *data);

extern TSS2_RC Fapi_CreateSeal_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    char     const *type,
    size_t          size,
    char     const *policyPath,
    char     const *authValue,
    uint8_t  const *data);

extern TSS2_RC Fapi_CreateSeal_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_Unseal(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint8_t       **data,
    size_t         *size);

extern TSS2_RC Fapi_Unseal_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_Unseal_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **data,
    size_t         *size);

/* Policy functions */

extern TSS2_RC Fapi_ExportPolicy(
    FAPI_CONTEXT   *context,
    char     const *path,
    char          **jsonPolicy);

extern TSS2_RC Fapi_ExportPolicy_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_ExportPolicy_Finish(
    FAPI_CONTEXT   *context,
    char          **jsonPolicy);

extern TSS2_RC Fapi_AuthorizePolicy(
    FAPI_CONTEXT   *context,
    char     const *policyPath,
    char     const *keyPath,
    uint8_t  const *policyRef,
    size_t          policyRefSize);

extern TSS2_RC Fapi_AuthorizePolicy_Async(
    FAPI_CONTEXT   *context,
    char     const *policyPath,
    char     const *keyPath,
    uint8_t  const *policyRef,
    size_t          policyRefSize);

extern TSS2_RC Fapi_AuthorizePolicy_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_WriteAuthorizeNv(
    FAPI_CONTEXT   *context,
    char     const *nvPath,
    char     const *policyPath);

extern TSS2_RC Fapi_WriteAuthorizeNv_Async(
    FAPI_CONTEXT   *context,
    char     const *nvPath,
    char     const *policyPath);

extern TSS2_RC Fapi_WriteAuthorizeNv_Finish(
    FAPI_CONTEXT   *context);

/* Attestation functions */

extern TSS2_RC Fapi_PcrRead(
    FAPI_CONTEXT   *context,
    uint32_t        pcrIndex,
    uint8_t       **pcrValue,
    size_t         *pcrValueSize,
    char          **pcrLog);

extern TSS2_RC Fapi_PcrRead_Async(
    FAPI_CONTEXT   *context,
    uint32_t        pcrIndex);

extern TSS2_RC Fapi_PcrRead_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **pcrValue,
    size_t         *pcrValueSize,
    char          **pcrLog);

extern TSS2_RC Fapi_PcrExtend(
    FAPI_CONTEXT   *context,
    uint32_t        pcr,
    uint8_t  const *data,
    size_t          dataSize,
    char     const *logData);

extern TSS2_RC Fapi_PcrExtend_Async(
    FAPI_CONTEXT   *context,
    uint32_t        pcr,
    uint8_t  const *data,
    size_t          dataSize,
    char     const *logData);

extern TSS2_RC Fapi_PcrExtend_Finish(
    FAPI_CONTEXT   *context);


extern TSS2_RC Fapi_Quote(
    FAPI_CONTEXT   *context,
    uint32_t       *pcrList,
    size_t          pcrListSize,
    char     const *keyPath,
    char     const *quoteType,
    uint8_t  const *qualifyingData,
    size_t          qualifyingDataSize,
    char          **quoteInfo,
    uint8_t       **signature,
    size_t         *signatureSize,
    char          **pcrLog,
    char          **certificate);

extern TSS2_RC Fapi_Quote_Async(
    FAPI_CONTEXT   *context,
    uint32_t       *pcrList,
    size_t          pcrListSize,
    char     const *keyPath,
    char     const *quoteType,
    uint8_t  const *qualifyingData,
    size_t          qualifyingDataSize);

extern TSS2_RC Fapi_Quote_Finish(
    FAPI_CONTEXT  *context,
    char         **quoteInfo,
    uint8_t      **signature,
    size_t        *signatureSize,
    char          **pcrLog,
    char          **certificate);

extern TSS2_RC Fapi_VerifyQuote(
    FAPI_CONTEXT   *context,
    char     const *publicKeyPath,
    uint8_t  const *qualifyingData,
    size_t          qualifyingDataSize,
    char     const *quoteInfo,
    uint8_t  const *signature,
    size_t          signatureSize,
    char     const *pcrLog);

extern TSS2_RC Fapi_VerifyQuote_Async(
    FAPI_CONTEXT   *context,
    char     const *publicKeyPath,
    uint8_t  const *qualifyingData,
    size_t          qualifyingDataSize,
    char     const *quoteInfo,
    uint8_t  const *signature,
    size_t          signatureSize,
    char     const *pcrLog);

extern TSS2_RC Fapi_VerifyQuote_Finish(
    FAPI_CONTEXT   *context);

/* NV functions */

extern TSS2_RC Fapi_CreateNv(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *type,
    size_t        size,
    char   const *policyPath,
    char   const *authValue);

extern TSS2_RC Fapi_CreateNv_Async(
    FAPI_CONTEXT *context,
    char   const *path,
    char   const *type,
    size_t        size,
    char   const *policyPath,
    char   const *authValue);

extern TSS2_RC Fapi_CreateNv_Finish(
    FAPI_CONTEXT *context);

extern TSS2_RC Fapi_NvRead(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint8_t      **data,
    size_t        *size,
    char         **logData);

extern TSS2_RC Fapi_NvRead_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_NvRead_Finish(
    FAPI_CONTEXT   *context,
    uint8_t       **data,
    size_t         *size,
    char          **logData);

extern TSS2_RC Fapi_NvWrite(
    FAPI_CONTEXT  *context,
    char    const *path,
    uint8_t const *data,
    size_t         size);

extern TSS2_RC Fapi_NvWrite_Async(
    FAPI_CONTEXT  *context,
    char    const *path,
    uint8_t const *data,
    size_t         size);

extern TSS2_RC Fapi_NvWrite_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_NvExtend(
    FAPI_CONTEXT  *context,
    char    const *path,
    uint8_t const *data,
    size_t         size,
    char    const *logData);

extern TSS2_RC Fapi_NvExtend_Async(
    FAPI_CONTEXT  *context,
    char    const *path,
    uint8_t const *data,
    size_t         size,
    char    const *logData);

extern TSS2_RC Fapi_NvExtend_Finish(
    FAPI_CONTEXT  *context);

extern TSS2_RC Fapi_NvIncrement(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_NvIncrement_Async(
    FAPI_CONTEXT   *context,
    char     const *path);

extern TSS2_RC Fapi_NvIncrement_Finish(
    FAPI_CONTEXT   *context);

extern TSS2_RC Fapi_NvSetBits(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint64_t        bitmap);

extern TSS2_RC Fapi_NvSetBits_Async(
    FAPI_CONTEXT   *context,
    char     const *path,
    uint64_t        bitmap);

extern TSS2_RC Fapi_NvSetBits_Finish(
    FAPI_CONTEXT   *context);

/*
extern typedef TSS2_RC (*Fapi_CB_Auth)(
    FAPI_CONTEXT   *context,
    char     const *description,
    char          **auth,
    void           *userData);
*/

extern TSS2_RC Fapi_SetAuthCB(
    FAPI_CONTEXT   *context,
    Fapi_CB_Auth    callback,
    void           *userData);

/*
extern typedef TSS2_RC (*Fapi_CB_Branch)(
    FAPI_CONTEXT   *context,
    char     const *description,
    char    const **branchNames,
    size_t          numBranches,
    size_t         *selectedBranch,
    void           *userData);
*/

extern TSS2_RC Fapi_SetBranchCB(
    FAPI_CONTEXT   *context,
    Fapi_CB_Branch  callback,
    void           *userData);

/*
extern typedef TSS2_RC (*Fapi_CB_Sign)(
    FAPI_CONTEXT   *context,
    char     const *description,
    char     const *publicKey,
    char     const *publicKeyHint,
    uint32_t        hashAlg,
    uint8_t  const *dataToSign,
    size_t          dataToSignSize,
    uint8_t       **signature,
    size_t         *signatureSize,
    void           *userData);
*/

extern TSS2_RC Fapi_SetSignCB(
    FAPI_CONTEXT   *context,
    Fapi_CB_Sign    callback,
    void           *userData);

/*
extern typedef TSS2_RC (*Fapi_CB_PolicyAction)(
    FAPI_CONTEXT   *context,
    char     const *action,
    void           *userData);
*/

extern TSS2_RC Fapi_SetPolicyActionCB(
    FAPI_CONTEXT        *context,
    Fapi_CB_PolicyAction callback,
    void                *userData);
