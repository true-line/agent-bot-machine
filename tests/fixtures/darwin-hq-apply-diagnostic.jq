# Print only recognized product messages and fixed exit codes from the first diagnostic.
([split("\n")[] | fromjson? | objects | select(.diagnostic and (.message|type=="string"))] | first) as $d
| if $d == null then "Machine did not emit a recognized diagnostic record" else
  ($d.diagnostic | if IN("MM_MEMBERS_APPLY_FAILED","MM_MEMBERS_NOT_APPROVED","MM_MEMBERS_PLAN_FAILED") then . else "other" end) as $id
  | ["cannot verify prior HQ apply receipt", "cannot check the host", "cannot write the receipt",
     "approved dedicated HQ pairing changed", "approved HQ pairing is unavailable",
     "upgrade requires its exact in-progress root receipt", "reviewed HQ plist or its prepared replacement changed",
     "dedicated HQ did not confirm its previously paired Machine", "HQ did not confirm the expected owner endpoint and available signer",
     "preserving endpoint while its HQ process may still exist", "preserving busy HQ endpoint",
     "preserved HQ transition evidence after stop", "preserved HQ transition evidence after attempted swap",
     "missing approved HQ socket directory", "protected HQ runtime directory changed before stop",
     "cannot identify the approved HQ job to stop", "cannot identify the running HQ process to stop",
     "launchd HQ process does not run under the dedicated service UID", "preserving changed or unobserved HQ endpoint before stop",
     "preserving changed HQ endpoint or process at recorded stop", "cannot confirm reviewed HQ job stopped",
     "reviewed HQ process remains registered after bootout", "cannot verify the registered HQ job after bootout",
     "preserving a different or unrecorded HQ process after bootout",
     "protected HQ runtime directory changed after stop", "preserving changed or unverified HQ owner-control endpoint",
     "preserving a listening HQ owner-control endpoint", "cannot verify the HQ owner-control endpoint is inactive",
     "owner-control socket has unexpected type, owner or mode", "mode 0755, expected 0666", "mode 0700, expected 0666",
     "owner-control socket was replaced during publication", "owner-control socket disappeared during publication",
     "owner control socket path already occupied or inaccessible", "cannot verify the approved job before rollback",
     "cannot inspect the launchd owner-control endpoint",
     "guarded unlink is unavailable", "unexpected owner pairing lock", "unexpected owner pairing evidence",
     "bootout failed", "no such file or directory",
     "launchd did not publish the owner-control socket before the deadline",
     "cannot confirm the HQ job was unloaded",
     "preserving an unrecognized HQ job during upgrade rollback", "preserving endpoint without exact recorded stop provenance",
     "HQ did not confirm its original Machine hardware signer",
     "previous HQ release, Machine pairing and original hardware signer verified after rollback",
     "permission denied", "operation not permitted", "resource temporarily unavailable", "invalid argument"] as $known
  | $d.message | split("\n") | .[:2] | map(. as $line | [$known[] | select(. as $key | $line | contains($key))]
      + ([$line | scan("query launched HQ as approved owner: sudo exit status (?:1|3|4|10|42)\\b")] | unique)
    | if length==0 then "unclassified" else join(", ") end)
  | "Machine diagnostic " + $id + ": " + join(" / ")
  end
