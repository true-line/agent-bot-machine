// The public SecTrustedApplicationCopyData API returns the display path on
// macOS. A legacy Keychain ACL stores its actual code requirement separately
// in its CSSM code-signature subject. Inspect an in-memory access made from
// the original trusted application, even if its old keg is gone from disk.
#include <Security/Security.h>
#include <Security/cssmapple.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

static void free_list(CSSM_LIST list) {
    CSSM_LIST_ELEMENT *next;
    for (CSSM_LIST_ELEMENT *element = list.Head; element; element = next) {
        next = element->NextElement;
        if (element->ElementType == CSSM_LIST_ELEMENT_SUBLIST)
            free_list(element->Element.Sublist);
        else if (element->ElementType == CSSM_LIST_ELEMENT_DATUM)
            free(element->Element.Word.Data);
        free(element);
    }
}

static bool word(const CSSM_LIST_ELEMENT *element, CSSM_WORDID_TYPE id) {
    return element && element->ElementType == CSSM_LIST_ELEMENT_WORDID && element->WordID == id;
}

// Old unsigned executables have no designated requirement. Preserve their
// same-path operation only when the stored legacy code hash also matches.
// The zero tag distinguishes this form from Apple's signed requirement blob.
static CFDataRef unsigned_identity(CSSM_DATA hash, CSSM_DATA path) {
    if (!hash.Data || !path.Data || path.Length < 2 || path.Length > PATH_MAX ||
        path.Data[0] != '/' || memchr(path.Data, 0, path.Length) != path.Data + path.Length - 1) return NULL;
    UInt8 bytes[1 + 20 + PATH_MAX] = {0};
    memcpy(bytes + 1, hash.Data, 20);
    memcpy(bytes + 21, path.Data, path.Length);
    return CFDataCreate(NULL, bytes, 21 + path.Length);
}

// SecAccessCreate produces one standard threshold list for the supplied
// application. Admit only the known legacy form or one signed requirement.
static CFDataRef copy_identity(const CSSM_LIST *list) {
    const CSSM_LIST_ELEMENT *head = list->Head;
    if (!word(head, CSSM_ACL_SUBJECT_TYPE_THRESHOLD)) return NULL;
    const CSSM_LIST_ELEMENT *threshold = head->NextElement;
    if (!word(threshold, 1) || !word(threshold->NextElement, 2)) return NULL;
    const CSSM_LIST_ELEMENT *app = threshold->NextElement->NextElement;
    if (!app || app->ElementType != CSSM_LIST_ELEMENT_SUBLIST) return NULL;
    const CSSM_LIST_ELEMENT *prompt = app->NextElement;
    if (!prompt || prompt->ElementType != CSSM_LIST_ELEMENT_SUBLIST || prompt->NextElement ||
        !word(prompt->Element.Sublist.Head, CSSM_ACL_SUBJECT_TYPE_KEYCHAIN_PROMPT)) return NULL;
    const CSSM_LIST_ELEMENT *code = app->Element.Sublist.Head;
    if (!word(code, CSSM_ACL_SUBJECT_TYPE_CODE_SIGNATURE)) return NULL;
    const CSSM_LIST_ELEMENT *type = code->NextElement;
    if (!word(type, CSSM_ACL_CODE_SIGNATURE_OSX)) return NULL;
    const CSSM_LIST_ELEMENT *hash = type->NextElement;
    if (!hash || hash->ElementType != CSSM_LIST_ELEMENT_DATUM || hash->Element.Word.Length != 20) return NULL;
    const CSSM_LIST_ELEMENT *path = hash->NextElement;
    if (!path || path->ElementType != CSSM_LIST_ELEMENT_DATUM) return NULL;
    const CSSM_LIST_ELEMENT *req = path->NextElement;
    if (!req) return unsigned_identity(hash->Element.Word, path->Element.Word);
    if (req->ElementType != CSSM_LIST_ELEMENT_DATUM || req->NextElement) return NULL;
    const CSSM_DATA bytes = req->Element.Word;
    if (!bytes.Data || !bytes.Length || bytes.Length > 65536) return NULL;
    CFDataRef data = CFDataCreate(NULL, bytes.Data, bytes.Length);
    SecRequirementRef parsed = NULL;
    if (!data || SecRequirementCreateWithData(data, kSecCSDefaultFlags, &parsed) != errSecSuccess) {
        if (data) CFRelease(data);
        return NULL;
    }
    CFRelease(parsed);
    return data;
}

CFDataRef keyd_copy_trusted_identity(SecTrustedApplicationRef app) {
    CFArrayRef apps = CFArrayCreate(NULL, (const void **)&app, 1, &kCFTypeArrayCallBacks);
    if (!apps) return NULL;
    SecAccessRef access = NULL;
    OSStatus status = SecAccessCreate(CFSTR("keyd"), apps, &access);
    CFRelease(apps);
    if (status != errSecSuccess || !access) return NULL;
    CSSM_ACL_OWNER_PROTOTYPE *owner = NULL;
    CSSM_ACL_ENTRY_INFO *entries = NULL;
    uint32 count = 0;
    status = SecAccessGetOwnerAndACL(access, &owner, &count, &entries);
    CFRelease(access);
    if (status != errSecSuccess) return NULL;

    // The SDK returns caller-owned CSSM graphs allocated with the standard
    // allocator. Only the generated decrypt entry contains our supplied app.
    CFDataRef result = NULL;
    size_t decrypt_entries = 0;
    for (uint32 i = 0; i < count; i++) {
        CSSM_ACL_ENTRY_PROTOTYPE *entry = &entries[i].EntryPublicInfo;
        for (uint32 j = 0; j < entry->Authorization.NumberOfAuthTags; j++) {
            if (entry->Authorization.AuthTags[j] == CSSM_ACL_AUTHORIZATION_DECRYPT) {
                if (++decrypt_entries == 1) result = copy_identity(&entry->TypedSubject);
            }
        }
        free_list(entry->TypedSubject);
        free(entry->Authorization.AuthTags);
        free(entry->TimeRange.StartDate.Data);
        free(entry->TimeRange.EndDate.Data);
    }
    free(entries);
    if (owner) { free_list(owner->TypedSubject); free(owner); }
    if (decrypt_entries != 1 && result) { CFRelease(result); return NULL; }
    return result;
}
