# EXIT trap for the disposable hosted custody test. The channel and stage
# were created exclusively before this trap was installed.
cleanup_role() {
    local status=$? failed=0
    trap - EXIT
    if "$made_role"; then sudo -n dscl . -delete "/Users/$role" || failed=1; fi
    if "$made_group"; then sudo -n dscl . -delete "/Groups/$role" || failed=1; fi
    if "$made_home"; then sudo -n rm -rf "$role_home" || failed=1; fi
    rmdir "$channel" || failed=1
    rm -rf "$temp" || failed=1
    if [[ "$status" != 0 ]]; then exit "$status"; fi
    exit "$failed"
}
