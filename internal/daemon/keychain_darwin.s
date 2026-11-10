//go:build darwin

#include "textflag.h"

TEXT kc_dlsym_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_dlsym(SB)
GLOBL	·kc_dlsym_trampoline_addr(SB), RODATA, $8
DATA	·kc_dlsym_trampoline_addr(SB)/8, $kc_dlsym_trampoline<>(SB)

TEXT kc_CFDataCreate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFDataCreate(SB)
GLOBL	·kc_CFDataCreate_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFDataCreate_trampoline_addr(SB)/8, $kc_CFDataCreate_trampoline<>(SB)

TEXT kc_CFDataGetLength_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFDataGetLength(SB)
GLOBL	·kc_CFDataGetLength_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFDataGetLength_trampoline_addr(SB)/8, $kc_CFDataGetLength_trampoline<>(SB)

TEXT kc_CFDataGetBytes_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFDataGetBytes(SB)
GLOBL	·kc_CFDataGetBytes_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFDataGetBytes_trampoline_addr(SB)/8, $kc_CFDataGetBytes_trampoline<>(SB)

TEXT kc_CFPropertyListCreateWithData_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFPropertyListCreateWithData(SB)
GLOBL	·kc_CFPropertyListCreateWithData_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFPropertyListCreateWithData_trampoline_addr(SB)/8, $kc_CFPropertyListCreateWithData_trampoline<>(SB)

TEXT kc_CFStringCreateWithBytes_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFStringCreateWithBytes(SB)
GLOBL	·kc_CFStringCreateWithBytes_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFStringCreateWithBytes_trampoline_addr(SB)/8, $kc_CFStringCreateWithBytes_trampoline<>(SB)

TEXT kc_CFDictionaryCreateMutable_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFDictionaryCreateMutable(SB)
GLOBL	·kc_CFDictionaryCreateMutable_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFDictionaryCreateMutable_trampoline_addr(SB)/8, $kc_CFDictionaryCreateMutable_trampoline<>(SB)

TEXT kc_CFDictionarySetValue_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFDictionarySetValue(SB)
GLOBL	·kc_CFDictionarySetValue_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFDictionarySetValue_trampoline_addr(SB)/8, $kc_CFDictionarySetValue_trampoline<>(SB)

TEXT kc_CFArrayCreate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFArrayCreate(SB)
GLOBL	·kc_CFArrayCreate_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFArrayCreate_trampoline_addr(SB)/8, $kc_CFArrayCreate_trampoline<>(SB)

TEXT kc_CFArrayGetCount_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFArrayGetCount(SB)
GLOBL	·kc_CFArrayGetCount_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFArrayGetCount_trampoline_addr(SB)/8, $kc_CFArrayGetCount_trampoline<>(SB)

TEXT kc_CFArrayGetValueAtIndex_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFArrayGetValueAtIndex(SB)
GLOBL	·kc_CFArrayGetValueAtIndex_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFArrayGetValueAtIndex_trampoline_addr(SB)/8, $kc_CFArrayGetValueAtIndex_trampoline<>(SB)

TEXT kc_CFRelease_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_CFRelease(SB)
GLOBL	·kc_CFRelease_trampoline_addr(SB), RODATA, $8
DATA	·kc_CFRelease_trampoline_addr(SB)/8, $kc_CFRelease_trampoline<>(SB)

TEXT kc_SecItemCopyMatching_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecItemCopyMatching(SB)
GLOBL	·kc_SecItemCopyMatching_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecItemCopyMatching_trampoline_addr(SB)/8, $kc_SecItemCopyMatching_trampoline<>(SB)

TEXT kc_SecItemAdd_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecItemAdd(SB)
GLOBL	·kc_SecItemAdd_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecItemAdd_trampoline_addr(SB)/8, $kc_SecItemAdd_trampoline<>(SB)

TEXT kc_SecItemUpdate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecItemUpdate(SB)
GLOBL	·kc_SecItemUpdate_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecItemUpdate_trampoline_addr(SB)/8, $kc_SecItemUpdate_trampoline<>(SB)

TEXT kc_SecItemDelete_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecItemDelete(SB)
GLOBL	·kc_SecItemDelete_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecItemDelete_trampoline_addr(SB)/8, $kc_SecItemDelete_trampoline<>(SB)

TEXT kc_SecTrustedApplicationCreateFromPath_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecTrustedApplicationCreateFromPath(SB)
GLOBL	·kc_SecTrustedApplicationCreateFromPath_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecTrustedApplicationCreateFromPath_trampoline_addr(SB)/8, $kc_SecTrustedApplicationCreateFromPath_trampoline<>(SB)

TEXT kc_SecTrustedApplicationValidateWithPath_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecTrustedApplicationValidateWithPath(SB)
GLOBL	·kc_SecTrustedApplicationValidateWithPath_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecTrustedApplicationValidateWithPath_trampoline_addr(SB)/8, $kc_SecTrustedApplicationValidateWithPath_trampoline<>(SB)

TEXT kc_SecTrustedApplicationCopyData_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecTrustedApplicationCopyData(SB)
GLOBL	·kc_SecTrustedApplicationCopyData_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecTrustedApplicationCopyData_trampoline_addr(SB)/8, $kc_SecTrustedApplicationCopyData_trampoline<>(SB)

TEXT kc_SecAccessCreate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecAccessCreate(SB)
GLOBL	·kc_SecAccessCreate_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecAccessCreate_trampoline_addr(SB)/8, $kc_SecAccessCreate_trampoline<>(SB)

TEXT kc_SecAccessCopyMatchingACLList_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecAccessCopyMatchingACLList(SB)
GLOBL	·kc_SecAccessCopyMatchingACLList_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecAccessCopyMatchingACLList_trampoline_addr(SB)/8, $kc_SecAccessCopyMatchingACLList_trampoline<>(SB)

TEXT kc_SecACLCopyContents_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecACLCopyContents(SB)
GLOBL	·kc_SecACLCopyContents_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecACLCopyContents_trampoline_addr(SB)/8, $kc_SecACLCopyContents_trampoline<>(SB)

TEXT kc_SecACLSetContents_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecACLSetContents(SB)
GLOBL	·kc_SecACLSetContents_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecACLSetContents_trampoline_addr(SB)/8, $kc_SecACLSetContents_trampoline<>(SB)

TEXT kc_SecKeychainItemCopyAccess_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainItemCopyAccess(SB)
GLOBL	·kc_SecKeychainItemCopyAccess_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainItemCopyAccess_trampoline_addr(SB)/8, $kc_SecKeychainItemCopyAccess_trampoline<>(SB)

TEXT kc_SecKeychainItemCopyAttributesAndData_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainItemCopyAttributesAndData(SB)
GLOBL	·kc_SecKeychainItemCopyAttributesAndData_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainItemCopyAttributesAndData_trampoline_addr(SB)/8, $kc_SecKeychainItemCopyAttributesAndData_trampoline<>(SB)

TEXT kc_SecKeychainItemFreeContent_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainItemFreeContent(SB)
GLOBL	·kc_SecKeychainItemFreeContent_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainItemFreeContent_trampoline_addr(SB)/8, $kc_SecKeychainItemFreeContent_trampoline<>(SB)

TEXT kc_SecKeychainCreate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainCreate(SB)
GLOBL	·kc_SecKeychainCreate_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainCreate_trampoline_addr(SB)/8, $kc_SecKeychainCreate_trampoline<>(SB)

TEXT kc_SecKeychainOpen_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainOpen(SB)
GLOBL	·kc_SecKeychainOpen_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainOpen_trampoline_addr(SB)/8, $kc_SecKeychainOpen_trampoline<>(SB)

TEXT kc_SecKeychainUnlock_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainUnlock(SB)
GLOBL	·kc_SecKeychainUnlock_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainUnlock_trampoline_addr(SB)/8, $kc_SecKeychainUnlock_trampoline<>(SB)

TEXT kc_SecKeychainSetUserInteractionAllowed_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainSetUserInteractionAllowed(SB)
GLOBL	·kc_SecKeychainSetUserInteractionAllowed_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainSetUserInteractionAllowed_trampoline_addr(SB)/8, $kc_SecKeychainSetUserInteractionAllowed_trampoline<>(SB)

TEXT kc_SecKeychainCopyDefault_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainCopyDefault(SB)
GLOBL	·kc_SecKeychainCopyDefault_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainCopyDefault_trampoline_addr(SB)/8, $kc_SecKeychainCopyDefault_trampoline<>(SB)

TEXT kc_SecKeychainSetDefault_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainSetDefault(SB)
GLOBL	·kc_SecKeychainSetDefault_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainSetDefault_trampoline_addr(SB)/8, $kc_SecKeychainSetDefault_trampoline<>(SB)

TEXT kc_SecKeychainGetStatus_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainGetStatus(SB)
GLOBL	·kc_SecKeychainGetStatus_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainGetStatus_trampoline_addr(SB)/8, $kc_SecKeychainGetStatus_trampoline<>(SB)

TEXT kc_SecKeychainSetSettings_trampoline<>(SB),NOSPLIT,$0-0
	JMP	kc_SecKeychainSetSettings(SB)
GLOBL	·kc_SecKeychainSetSettings_trampoline_addr(SB), RODATA, $8
DATA	·kc_SecKeychainSetSettings_trampoline_addr(SB)/8, $kc_SecKeychainSetSettings_trampoline<>(SB)
