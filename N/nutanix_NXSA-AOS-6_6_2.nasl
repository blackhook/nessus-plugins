#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174898);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2021-4037",
    "CVE-2021-4197",
    "CVE-2021-25220",
    "CVE-2021-33655",
    "CVE-2021-33656",
    "CVE-2022-0171",
    "CVE-2022-0494",
    "CVE-2022-1011",
    "CVE-2022-1012",
    "CVE-2022-1158",
    "CVE-2022-1184",
    "CVE-2022-1462",
    "CVE-2022-1729",
    "CVE-2022-1786",
    "CVE-2022-1789",
    "CVE-2022-2153",
    "CVE-2022-2585",
    "CVE-2022-2588",
    "CVE-2022-2663",
    "CVE-2022-2795",
    "CVE-2022-2905",
    "CVE-2022-20158",
    "CVE-2022-20368",
    "CVE-2022-21125",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21626",
    "CVE-2022-21628",
    "CVE-2022-23816",
    "CVE-2022-26373",
    "CVE-2022-28693",
    "CVE-2022-28893",
    "CVE-2022-29581",
    "CVE-2022-29582",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-30594",
    "CVE-2022-36123",
    "CVE-2022-36879",
    "CVE-2022-36946",
    "CVE-2022-38177",
    "CVE-2022-38178",
    "CVE-2022-40674",
    "CVE-2022-41222",
    "CVE-2022-41974",
    "CVE-2022-42703",
    "CVE-2022-42898",
    "CVE-2022-45143",
    "CVE-2023-21830",
    "CVE-2023-21843",
    "CVE-2023-22809"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.6.2)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.6.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.6.2 advisory.

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

  - The JsonErrorReportValve in Apache Tomcat 8.5.83, 9.0.40 to 9.0.68 and 10.1.0-M1 to 10.1.1 did not escape
    the type, message or description values. In some circumstances these are constructed from user provided
    data and it was therefore possible for users to supply values that invalidated or manipulated the JSON
    output. (CVE-2022-45143)

  - In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-
    provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append
    arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected
    versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a
    -- argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
    (CVE-2023-22809)

  - BIND 9.11.0 -> 9.11.36 9.12.0 -> 9.16.26 9.17.0 -> 9.18.0 BIND Supported Preview Editions: 9.11.4-S1 ->
    9.11.36-S1 9.16.8-S1 -> 9.16.26-S1 Versions of BIND 9 earlier than those shown - back to 9.1.0, including
    Supported Preview Editions - are also believed to be affected but have not been tested as they are EOL.
    The cache could become poisoned with incorrect records leading to queries being made to the wrong servers,
    which might also result in false information being returned to clients. (CVE-2021-25220)

  - By flooding the target resolver with queries exploiting this flaw an attacker can significantly impair the
    resolver's performance, effectively denying legitimate clients access to the DNS resolution service.
    (CVE-2022-2795)

  - multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to obtain root access, as exploited
    alone or in conjunction with CVE-2022-41973. Local users able to write to UNIX domain sockets can bypass
    access controls and manipulate the multipath setup. This can lead to local privilege escalation to root.
    This occurs because an attacker can repeat a keyword, which is mishandled because arithmetic ADD is used
    instead of bitwise OR. (CVE-2022-41974)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Serialization). Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf;
    Oracle GraalVM Enterprise Edition: 20.3.8 and 21.3.4. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2023-21830)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Sound). Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf, 11.0.17,
    17.0.5, 19.0.1; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and 22.3.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2023-21843)

  - Mis-trained branch predictions for return instructions may allow arbitrary speculative code execution
    under certain microarchitecture-dependent conditions. (CVE-2022-29900)

  - Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can
    hijack return instructions to achieve arbitrary speculative code execution under certain
    microarchitecture-dependent conditions. (CVE-2022-29901)

  - A flaw was found in KVM. When updating a guest's page table entry, vm_pgoff was improperly used as the
    offset to get the page's pfn. As vaddr and vm_pgoff are controllable by user-mode processes, this flaw
    allows unprivileged local users on the host to write outside the userspace region and potentially corrupt
    the kernel, resulting in a denial of service condition. (CVE-2022-1158)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due to a race condition in io_uring
    timeouts. This can be triggered by a local user who has no access to any user namespace; however, the race
    condition perhaps can only be exploited infrequently. (CVE-2022-29582)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A use-after-free flaw was found in the Linux kernel's io_uring subsystem in the way a user sets up a ring
    with IORING_SETUP_IOPOLL with more than one task completing submissions on this ring. This flaw allows a
    local user to crash or escalate their privileges on the system. (CVE-2022-1786)

  - With shadow paging enabled, the INVPCID instruction results in a call to kvm_mmu_invpcid_gva. If INVPCID
    is executed with CR0.PG=0, the invlpg callback is not set and the result is a NULL pointer dereference.
    (CVE-2022-1789)

  - A use-after-free flaw was found in fs/ext4/namei.c:dx_insert_block() in the Linux kernel's filesystem sub-
    component. This flaw allows a local attacker with a user privilege to cause a denial of service.
    (CVE-2022-1184)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - The Linux kernel before 5.18.13 lacks a certain clear operation for the block starting symbol (.bss). This
    allows Xen PV guest OS users to cause a denial of service or gain privileges. (CVE-2022-36123)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through 5.18.14 allows remote
    attackers to cause a denial of service (panic) because, in the case of an nf_queue verdict with a one-byte
    nfta_payload attribute, an skb_pull can encounter a negative skb->len. (CVE-2022-36946)

  - mm/rmap.c in the Linux kernel before 5.19.7 has a use-after-free related to leaf anon_vma double reuse.
    (CVE-2022-42703)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow
    an authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c. (CVE-2022-40674)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Security). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf,
    11.0.16.1, 17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM
    Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2022-21619)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JNDI). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf, 11.0.16.1,
    17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2022-21624)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Security). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf,
    11.0.16.1; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTPS to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21626)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Lightweight HTTP Server). Supported versions that are affected are Oracle Java SE: 8u341,
    8u345-perf, 11.0.16.1, 17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2022-21628)

  - By spoofing the target resolver with responses that have a malformed ECDSA signature, an attacker can
    trigger a small memory leak. It is possible to gradually erode available memory to the point where named
    crashes for lack of resources. (CVE-2022-38177)

  - By spoofing the target resolver with responses that have a malformed EdDSA signature, an attacker can
    trigger a small memory leak. It is possible to gradually erode available memory to the point where named
    crashes for lack of resources. (CVE-2022-38178)

  - When setting font with malicous data by ioctl cmd PIO_FONT,kernel will write memory out of bounds.
    (CVE-2021-33656)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A race condition was found the Linux kernel in perf_event_open() which can be exploited by an unprivileged
    user to gain root privileges. The bug allows to build several exploit primitives such as kernel address
    information leak, arbitrary execution, etc. (CVE-2022-1729)

  - A memory leak problem was found in the TCP source port generation algorithm in net/ipv4/tcp.c due to the
    small table perturb size. This flaw may allow an attacker to information leak and may cause a denial of
    service problem. (CVE-2022-1012)

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - The SUNRPC subsystem in the Linux kernel through 5.17.2 can call xs_xprt_free before ensuring that sockets
    are in the intended state. (CVE-2022-28893)

  - An out-of-bounds read flaw was found in the Linux kernel's TeleTYpe subsystem. The issue occurs in how a
    user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage
    of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read
    unauthorized random data from memory. (CVE-2022-1462)

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root
    (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD
    CPU that supports Secure Encrypted Virtualization (SEV). (CVE-2022-0171)

  - mm/mremap.c in the Linux kernel before 5.13.3 has a use-after-free via a stale TLB because an rmap lock is
    not held during a PUD move. (CVE-2022-41222)

  - In bdi_put and bdi_unregister of backing-dev.c, there is a possible memory corruption due to a use after
    free. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-182815710References: Upstream kernel (CVE-2022-20158)

  - Product: AndroidVersions: Android kernelAndroid ID: A-224546354References: Upstream kernel
    (CVE-2022-20368)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - kernel: posix cpu timer use-after-free may lead to local privilege escalation (CVE-2022-2585)

  - A flaw was found in hw. Mis-trained branch predictions for return instructions may allow arbitrary
    speculative code execution under certain microarchitecture-dependent conditions. (CVE-2022-23816)
    (CVE-2022-28693)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.6.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17b5b3d6");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29581");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudoedit Extra Arguments Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '6.6.2', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.6.2 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.6.2', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.6.2 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
