# lockdownd vulnerabilities (RESEARCH)

**only for iOS 26.5, i don't know if these vulns exist in earlier versions, you need to check by yourself i hope this is valuable to someone, also check out mobileactivationd and securerom repos**

---

## startsession pairing record expiry bypass

address: `sub_10001f8c8` (handle_start_session)

the session startup reads the pairing record timestamp and compares it to current time, the expiry window comes from `sub_100004220` which hardcodes the value 2592000, exactly 30 days in seconds, now if the timestamp check passes it calls `sub_100003c04` to update, if update fails entire session is rejected

```c
v56 = sub_100003F0C(a1: v50, a2: &v96);
if (v56 != 0) {
    if (v57 > v96 + (double)sub_100004220())
        sub_100004050(a1: v50);
        goto LABEL_23;
```

the vulnerability is that the expiry comparison relies on a floating point timestamp stored in a plist at a path constructed with snprintf into a 1024 byte stack buffer using the format `%s/Library/Lockdown/pair_records/%s.plist`. if the lastpaireddate entry is missing from the plist, `sub_100003f0c` returns 0 and the expiry check is skipped entirely, and any host with a partial pair record can start a session without the timestamp gate

bypass 30 day session expiry, establish ssl session without a valid recent pairing

---

## ssl setup with cert verify disabled

address: `sub_1000ac4f8`

the ssl context is created with certificate verification explicitly disabled (congrats apple fr)

```c
_SSLSetEnableCertVerify(context: contextPtr, enableVerify: 0)
```

verification is done manually via sectrust, the trust object is anchored to the rootcertificate from the pairing record, if the pairing record does not contain a rootcertificate key, the function returns 0 and kills the ssl context... however because the anchor is set from the pair record, who controls the pair record also controls the trust anchor, any cert chain rooted there will pass verification

anyone who can write a pair record with a custom rootcertificate can create a trusted ssl session to lockdownd

---

## is_host_trusted untrusted hosts plist injection

address: `sub_100019ca8`

when the client passes options with `ignoreduntrustedlist: true`, the untrusted hosts check is completely skipped

```c
v13 = theDict == nullptr ||
      CFDictionaryGetValue(theDict, CFSTR("IgnoreUntrustedList")) != kCFBooleanTrue;
...
if ((v24 & 1) != 0) {
    v14 = nullptr;
}
```

the options dict comes directly from the incoming lockdown message with no authentication before this check point, a client that has not yet started a session can send ishosttrusted with options containing ignoreduntrustedlist=true and skip the untrusted host check, now the function then proceeds to call `sub_100017a88` which checks the actual pair record, but if the pair record check also passes via startsession pairing record (don't doubt me if im wrong), and the host is marked trusted 

bypass the untrusted hosts blocklist without any credential

---

## request dispatcher access control bitmap

address: `sub_10001c61c` (parse_message)

confirmed the access control check for unpaired clients uses a bitmask

```c
if (v5 == 4 && v8 <= 0x10 && ((1 << v8) & 0x1E604) != 0)
    return 0;
```

the mask `0x1e604` in lockdownd is `0001 1110 0110 0000 0100` i think i missed one 0 or 1, bits not set in this mask are not blocked for unpaired clients when the state is four, confirmed allowed requests for an unpaired client include getvalue (bit 3 = 0 in mask), getvaluecu (bit 4 = 0 in mask), and removevalue (bit 8 = 0 in mask), req code 23 (validateautomationrecord) has v8 = 23 which is above 0x10 so the check `v8 <= 0x10` lets it through entirely regardless of the bitmask

impact: an unpaired host can call getvalue, getvaluecu, removevalue, and validateautomationrecord on lockdownd without going through startsession, getvalue returns device identifiers and other fields. removevalue deletes pair record entries unauthenticated

---

## pairing record path traversal

address: `sub_100016160` (load_pair_record)

the pair record path is built using the hostid directly from the incoming lockdown request after only a check that it does not start with `..`

```c
sub_1000281C8(__s: buffer);
if ((*(unsigned short*)buffer ^ 0x2E2E | v18) == 0) {
    goto LABEL_9;
}
snprintf(__str, 0x400, "%s%s/%s.plist", v16,
         "/Library/Lockdown/pair_records", buffer);
```

the check catches only a hostid that starts with exactly the two bytes `0x2e2e` (the string `..`), a hostid like `valid/../../../etc/smth` passes the check because the first two bytes are `va` not `..`, this allows loading pair records from arbitrary filesystem paths by supplying a crafted hostid containing a traversal sequence after an initial valid prefix

read arbitrary plist files from the filesystem as pair records, forge pairing credentials using existing system plists

---

## removev alue allowed for unpaired clients

address: `sub_10001c61c` (parse_message) and getvalue dispatch chain

from the decompile of `sub_100016160` and the getvalue handler chain, getvalue calls `sub_100027d74` to read the resolved plist path, there is no check after path resolution that restricts which keys can be queried from an unpaired session, the domain field in the request is passed through to a dictionary lookup without scoping, combined with pairing record, an unpaired client can supply a hostid traversal to resolve a pair record from an arbitrary plist, then call getvalue against keys in that loaded record

additionally removevalue (request code 8) is not blocked for unpaired clients, the removevalue handler calls `sub_100004050` which deletes the resolved pair record, an unpaired client can therefore call removevalue with a crafted hostid to delete the resolved plist entry from an arbitrary filesystem path, subject to lockdownd process permissions

unauthenticated deletion of arbitrary pair record entries reachable by lockdownd, combined with path traversal produces a limited unauthenticated file operation primitive

---

## bonjour instance name constructed from attacker wifi mac address without length validation

address: `sub_100009bbc`

the function `sub_100009940` calls `sub_100009bbc` with the wifiaddress value read from the data store, inside `sub_100009bbc` the wifi mac address is passed to `cfstringcreatewithformat` and the result is then passed to `cfstringgetcstring` with a fixed 64 byte buffer

```c
if (CFStringGetCString(theString: v19, buffer, bufferSize: 64, encoding: 0x8000100u) != 0)
```

the mac address string `v18` is retrieved from `sub_1000097a0` and concatenated into the instance name format `%@@%@` or `%@@%@-%@-%ld`, the resulting string is truncated to 64 bytes by cfstringgetcstring, if a device has a malformed or controlled wifiaddress value in its data store (writable via setvalue for a paired session) the bonjour advertisement will emit a truncated or malformed instance name, the full service name is then constructed by dnssourceconstructfullname and stored back without validating length

separately, the function checks `remotepairingsEnabled()` and includes the remote pairing protocol version from `remotepairinggetcurrentwireprotocolversion` in the instance name, if this version value is influenced, the bonjour name can be crafted to contain special chars, the code does call cfstringfindandreplace to remove backslashes, leaving other dns chars unfiltered

you can influence the bonjour advertisement name broadcast over wifi. dns injection into local network bonjour traffic via malformed wifiaddress or remote pairing version fields

---

## validateautomationrecord bypasses unpaired acl entirely

address: `sub_10001c61c` (parse_message)

req code 23 (`validateautomationrecord`) is mapped via the final else branch in parse_message, the acl check is

```c
if (v5 == 4 && (unsigned int)v8 <= 0x10 && ((1 << v8) & 0x1E604) != 0)
    return 0;
```

v8 = 23 which is greater than 0x10 so the condition `v8 <= 0x10` is false and the check is entirely skipped, an unpaired client can send a validateautomationrecord request and it will reach the handler regardless of pairing state, the handler for this request was not fully resolved in this session but the dispatch table shows it is a code path beyond the getvalue or pair flows

from my perspective unpaired clients can invoke the validateautomationrecord handler, the handler attack surface is reachable without any auth.

---

## keybag and device lock state readable without pairing via getvalue dispatch

address: `sub_10000c960` and getvalue chain

`sub_10000c960` is a getvalue handler that checks `mkbgetdevicelockstate` and then queries biome for keybag lock status via objc msgsend on the biome device object, this handler is invoked through the getvalue dispatch chain which is reachable by unpaired clients

the function queries:
- device lock state via `mkbgetdevicelockstate`
- keybag locked state via biome `device.keybagLocked` publisher
- whether the device has been unlocked within a configurable hour window

this information leaks whether the device is in bfu (before first unlock) or afu (after first unlock) state, with usb access but no pairing record can probe this to determine whether data extraction

unauthenticated side channel leaks bfu vs afu state and keybag lock status to any usb client (golden finding for me xd)

---

## scpreferences written without caller authentication in setvalue handlers

addresses: `sub_10000a2c0` (enable_8021x_logging), `sub_10000a570` (enable_cltm_logging)

both functions write to scpreferences and call `scpreferencescommitchanges` and `scpreferencesapplychanges` without checking the connection auth state or pairing status at the point of write, the 8021x handler writes to `com.apple.eapolclient.plist` and the cltm handler writes to `osthermalstatus.plist`. these are conf preferences that affect network authentication and thermal logging

the 8021x handler sets `LogFlags` to `-1` (all bits set) when passed `kCFBooleanTrue`, enabling verbose logging system wide, the cltm handler hardcodes a log file path

```c
SCPreferencesSetValue(prefs: v15, key: CFSTR("logFile"), value: CFSTR("/var/logs/cltm.log"));
```

if these setvalue handlers are callable from a paired session without entitlement checks, they represent a persistent system configuration modification vector
NOTE! these are not directly reachable unpaired, but once a session is established, they becoming accessible

paired session (easily obtained via startsession pairing record and is_host_trusted) can enable verbose logging, modify network auth conf, and write to system plist files without checks beyond the session itself

---

## PACIBSP avoid / bypass approaches

### what pacibsp does for begginers

every function in lockdownd begins with `pacibsp` unfortunately and ends with either `retab` or `autibsp` before returning the pac instruction set on arm64e signs the link register using the instruction address of the stack pointer as a modifier, on return `retab` authenticates the stored lr before branching to it

this is confirmed from the binary, all queried pacibsp addresses correspond to function prologues, the paired retab instructions are found at the corresponding function epilogues (confirmed via the retab, it's returning epilogue addresses that correspond to functions starting with pacibsp)

### braa usage (indirect call auth)

at addresses `0x100006bfc` through `0x100006cc0` there are eight `braa x3, x2` instructions clustered together, braa performs an authenticated indirect branch using key a with x2 as the modifier, this is likely a vtable or function pointer dispatch table, probably the objc msgSend dispatch stubs or a similar indirect call, the clustering and identical instruction pattern suggests a generated stub section

this is significant because braa is harder to forge than an unprotected blr, but the security depends entirely on the integrity of x2 (the modifier, typically a pointer to the object) and x3 (the signed function pointer). if you can control object memory (heap corruption), you may control x2 allowing pac forgery for those specific call sites

### how pacibsp can be bypassed / avoided in lockdownd

there are multiple approaches depending on let's say attacker position for example

**approach 1: pac is irrelevant for logic bugs**

all vulnerabilities are all logic vulnerabilities, they do not require any code execution and therefore pac provides zero protection against them, an attacker exploiting timestamp or ignoreduntrustedlist bypass is manipulating, not redirecting the code, PAC is simply not on the threat model for these bugs

**approach 2: pac oracle via controlled crash**

on devices without a jailbreak, pac authentication failures trigger a kernel panic or a controlled signal, by causing deliberate authentication failures with varying pac values on known function pointers, an attacker with a controlled crash loop (e.g. via a persistent service restart) can attempt to oracle the pac value over time, this is slow but remains the classic forge by oracle appr

**approach 3: use a non pac return site**

the lockdownd has multiple `brk 0xc471` instructions, brk 0xc471 is the again let's say a trap for a pac auth failure by identifying code paths where a pac stripped pointer reaches a brk rather than being validated, an attacker can potentially reach brk sites and use the resulting signal handler state as a pivot. this is advanced and specific in my opinion

**approach 4: finding a function that does not pair pacibsp with retab**

from my researches in lockdownd, some code paths contain early returns via `goto` that bypass the normal epilogue, if any such path returns via a raw `ret` instead of `retab`, the stored lr is not authenticated on return. in the decompiled output of `sub_10000b518` (copy_keys_and_certs), multiple goto labels jump to `LABEL_40` cleanup then return the compiled epilogue. for those paths should still use retab, but edge cases in compiler generation for complex functions with many early exits are worth reviewing manually in the disassembly

**approach 5: heap spray to control the braa modifier (x2) in the vtable dispatch**

at the eight braa call sites between `0x100006bfc` and `0x100006cc0`, x2 is the modifier used to authenticate the function pointer in x3. if the object whose address becomes x2 is heap allocated and an attacker can control its contents via a heap corruption bug (i didn't found it but a general it's good to try this surface), the pac signature needed to forge x3 changes to one derived from the controlled x2, combined with a pac oracle this reduces the difficulty of pac forgery at those specific call sites

**approach 6: use the pairing record path traversal to read a plist containing a pre signed pointer**

this is theoretical but worth noting, if any plist is readable via the path traversal (happens to contain a binary blob that includes a valid signed pointer e.g. a serialized mach port right or a binary plist with pointer-width data), and if that data lands in a context where it is used as a pac signed pointer, it could serve as a pac gadget, this is deeply target specific and would require additional primitives beyond what i confirmed here

### summary

pac in this binary is well deployed at the abi level, every function entry and exit is covered the braa usage at the vtable dispatch sites is correct however pac is architectural protection against exploitation, not against the class of logic auth. I found controlable bugs or vulns whatever you want to call it i found. what is VERY IMPORTANT that pac does not protect against any of the vulnerabilities or bugs listed here

---

## now how to try this (i will drop PoC)

the following below describes how the confirmed bugs chain together into a full compromise

1. connect usb with no prior trust relationship
2. send ishosttrusted with `ignoreduntrustedlist: true` in options is_host_trusted skips the blocklist
3. send a crafted hostid containing a traversal path to load an existing system plist as a pair record (pairing record path traversal bug)
4. the loaded plist has no lastpaireddate key, first bug skips the 30 day expiry check (dumbest finding for me but ok)
5. the ssl anchor is now the rootcertificate in controlled plist, second bug allows a cert signed by any key in that plist to pass
6. session is now established without the trust prompt being shown to the user hehe
7. send getvalue and removevalue requests, 4th bug or vuln whatever allows these unpaired, and from within the established session any registered value is accessible
8. probe keybag state via the getvalue handler 9th vuln leaks bfu vs afu
9. if afu proceed to data extraction via startservice to spawn file relay or other lockdown services
10. if desired, call setvalue handlers to write to scpreferences 10th vuln 

you won't see nothing at any step, the trust window will not appear

---

## addresses

| bug | addr | funct name |
|---------|---------|---------------|
| 1 | 0x10001f8c8 | handle_start_session |
| 2 | 0x1000ac4f8 | ssl context setup |
| 3 | 0x100019ca8 | is_host_trusted |
| 4 | 0x10001c61c | parse_message |
| 5 | 0x100016160 | load_pair_record |
| 6 | 0x10001c61c and dispatch | getvalue/removevalue chain |
| 7 | 0x100009bbc | update_bonjour_service_instance_name |
| 8 | 0x10001c61c | parse_message (code 23) |
| 9 | 0x10000c960 | hasdevicebeenunlockedwithinnumberofhours |
| 10 | 0x10000a2c0 / 0x10000a570 | enable_8021x_logging / enable_cltm_logging |
| pac | 0x100006bfc...0x100006cc0 | braa vtable dispatch cluster |

i will upload PoC sooner when i finish more analsys for PAC avoiding and im publishing this as RESEARCH!!!
