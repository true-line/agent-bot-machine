#include "textflag.h"

TEXT mac_lock_fgetattrlist_trampoline<>(SB),NOSPLIT,$0-0
	JMP	mac_lock_fgetattrlist(SB)
GLOBL	·macGetattrlistAddr(SB), RODATA, $8
DATA	·macGetattrlistAddr(SB)/8, $mac_lock_fgetattrlist_trampoline<>(SB)
