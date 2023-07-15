##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2615-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(163692);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2021-4204",
    "CVE-2021-26341",
    "CVE-2021-33061",
    "CVE-2021-44879",
    "CVE-2021-45402",
    "CVE-2022-0264",
    "CVE-2022-0494",
    "CVE-2022-0617",
    "CVE-2022-1012",
    "CVE-2022-1016",
    "CVE-2022-1184",
    "CVE-2022-1198",
    "CVE-2022-1205",
    "CVE-2022-1508",
    "CVE-2022-1651",
    "CVE-2022-1652",
    "CVE-2022-1671",
    "CVE-2022-1679",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1789",
    "CVE-2022-1852",
    "CVE-2022-1966",
    "CVE-2022-1972",
    "CVE-2022-1974",
    "CVE-2022-1998",
    "CVE-2022-2318",
    "CVE-2022-20132",
    "CVE-2022-20154",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21127",
    "CVE-2022-21166",
    "CVE-2022-21180",
    "CVE-2022-21499",
    "CVE-2022-23222",
    "CVE-2022-26365",
    "CVE-2022-26490",
    "CVE-2022-29582",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-30594",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-33743",
    "CVE-2022-33981",
    "CVE-2022-34918"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2615-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2022:2615-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:2615-1 advisory.

  - Some AMD CPUs may transiently execute beyond unconditional direct branches, which may potentially result
    in data leakage. (CVE-2021-26341)

  - Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2021-33061)

  - An out-of-bounds (OOB) memory access flaw was found in the Linux kernel's eBPF due to an Improper Input
    Validation. This flaw allows a local attacker with a special privilege to crash the system or leak
    internal information. (CVE-2021-4204)

  - In gc_data_segment in fs/f2fs/gc.c in the Linux kernel before 5.16.3, special files are not considered,
    leading to a move_data_page NULL pointer dereference. (CVE-2021-44879)

  - The check_alu_op() function in kernel/bpf/verifier.c in the Linux kernel through v5.16-rc5 did not
    properly update bounds while handling the mov32 instruction, which allows local users to obtain
    potentially sensitive address information, aka a pointer leak. (CVE-2021-45402)

  - A vulnerability was found in the Linux kernel's eBPF verifier when handling internal data structures.
    Internal memory locations could be returned to userspace. A local attacker with the permissions to insert
    eBPF code to the kernel can use this to leak internal kernel memory details defeating some of the exploit
    mitigations in place for the kernel. This flaws affects kernel versions < v5.16-rc6 (CVE-2022-0264)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a
    use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel
    information leak problem caused by a local, unprivileged attacker. (CVE-2022-1016)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - A use-after-free vulnerabilitity was discovered in drivers/net/hamradio/6pack.c of linux that allows an
    attacker to crash linux kernel by simulating ax25 device using 6pack driver from user space.
    (CVE-2022-1198)

  - A NULL pointer dereference flaw was found in the Linux kernel's Amateur Radio AX.25 protocol functionality
    in the way a user connects with the protocol. This flaw allows a local user to crash the system.
    (CVE-2022-1205)

  - An out-of-bounds read flaw was found in the Linux kernel's io_uring module in the way a user triggers the
    io_read() function with some special parameters. This flaw allows a local user to read some memory out of
    bounds. (CVE-2022-1508)

  - A memory leak flaw was found in the Linux kernel in acrn_dev_ioctl in the drivers/virt/acrn/hsm.c function
    in how the ACRN Device Model emulates virtual NICs in VM. This flaw allows a local privileged attacker to
    leak unauthorized kernel information, causing a denial of service. (CVE-2022-1651)

  - Linux Kernel could allow a local attacker to execute arbitrary code on the system, caused by a concurrency
    use-after-free flaw in the bad_flp_intr function. By executing a specially-crafted program, an attacker
    could exploit this vulnerability to execute arbitrary code or cause a denial of service condition on the
    system. (CVE-2022-1652)

  - A NULL pointer dereference flaw was found in rxrpc_preparse_s in net/rxrpc/server_key.c in the Linux
    kernel. This flaw allows a local attacker to crash the system or leak internal kernel information.
    (CVE-2022-1671)

  - A use-after-free flaw was found in the Linux kernel's Atheros wireless adapter driver in the way a user
    forces the ath9k_htc_wait_for_target function to fail with some input messages. This flaw allows a local
    user to crash or potentially escalate their privileges on the system. (CVE-2022-1679)

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use
    after free both read or write when non synchronized between cleanup routine and firmware download routine.
    (CVE-2022-1734)

  - With shadow paging enabled, the INVPCID instruction results in a call to kvm_mmu_invpcid_gva. If INVPCID
    is executed with CR0.PG=0, the invlpg callback is not set and the result is a NULL pointer dereference.
    (CVE-2022-1789)

  - A NULL pointer dereference flaw was found in the Linux kernel's KVM module, which can lead to a denial of
    service in the x86_emulate_insn in arch/x86/kvm/emulate.c. This flaw occurs while executing an illegal
    instruction in guest in the Intel CPU. (CVE-2022-1852)

  - A use-after-free flaw was found in the Linux kernel's NFC core functionality due to a race condition
    between kobject creation and delete. This vulnerability allows a local attacker with CAP_NET_ADMIN
    privilege to leak kernel information. (CVE-2022-1974)

  - A use after free in the Linux kernel File System notify functionality was found in the way user triggers
    copy_info_records_to_user() call to fail in copy_event_to_user(). A local user could use this flaw to
    crash the system or potentially escalate their privileges on the system. (CVE-2022-1998)

  - In lg_probe and related functions of hid-lg.c and other USB HID files, there is a possible out of bounds
    read due to improper input validation. This could lead to local information disclosure if a malicious USB
    HID device were plugged in, with no additional execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-188677105References: Upstream
    kernel (CVE-2022-20132)

  - In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead
    to local escalation of privilege with System execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream
    kernel (CVE-2022-20154)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register read operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21127)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - Improper input validation for some Intel(R) Processors may allow an authenticated user to potentially
    cause a denial of service via local access. (CVE-2022-21180)

  - KGDB and KDB allow read and write access to kernel memory, and thus should be restricted during lockdown.
    An attacker with access to a serial port could trigger the debugger so it is important that the debugger
    respect the lockdown mode when/if it is triggered. (CVE-2022-21499)

  - There are use-after-free vulnerabilities caused by timer handler in net/rose/rose_timer.c of linux that
    allow attackers to crash linux kernel without any privileges. (CVE-2022-2318)

  - kernel/bpf/verifier.c in the Linux kernel through 5.15.14 allows local users to gain privileges because of
    the availability of pointer arithmetic via certain *_OR_NULL pointer types. (CVE-2022-23222)

  - Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text
    explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device
    frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740).
    Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to
    unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend
    (CVE-2022-33741, CVE-2022-33742). (CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due to a race condition in io_uring
    timeouts. This can be triggered by a local user who has no access to any user namespace; however, the race
    condition perhaps can only be exploited infrequently. (CVE-2022-29582)

  - Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution
    under certain microarchitecture-dependent conditions. (CVE-2022-29900)

  - Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29901)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - network backend may cause Linux netfront to use freed SKBs While adding logic to support XDP (eXpress Data
    Path), a code label was moved in a way allowing for SKBs having references (pointers) retained for further
    processing to nevertheless be freed. (CVE-2022-33743)

  - drivers/block/floppy.c in the Linux kernel before 5.17.6 is vulnerable to a denial of service, because of
    a concurrency use-after-free flaw after deallocating raw_cmd in the raw_cmd_ioctl function.
    (CVE-2022-33981)

  - An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init
    (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different
    vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an
    unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data
    in net/netfilter/nf_tables_api.c. (CVE-2022-34918)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/150300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1055117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1061840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1089644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1121726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201228");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201251");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-August/011728.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff71b63f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-30594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-33981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-34918");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34918");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150400.14.7.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.7.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.7.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.7.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.7.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.7.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.7.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.7.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.7.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.7.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / kernel-azure / etc');
}
