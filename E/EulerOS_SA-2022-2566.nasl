#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165936);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/26");

  script_cve_id(
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26140",
    "CVE-2020-26141",
    "CVE-2020-26142",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26146",
    "CVE-2020-26147",
    "CVE-2021-0920",
    "CVE-2021-0938",
    "CVE-2021-0941",
    "CVE-2021-3655",
    "CVE-2021-3744",
    "CVE-2021-3764",
    "CVE-2021-3772",
    "CVE-2021-4002",
    "CVE-2021-4037",
    "CVE-2021-4083",
    "CVE-2021-4135",
    "CVE-2021-4157",
    "CVE-2021-4159",
    "CVE-2021-20321",
    "CVE-2021-29650",
    "CVE-2021-33098",
    "CVE-2021-34556",
    "CVE-2021-35477",
    "CVE-2021-38209",
    "CVE-2021-39633",
    "CVE-2021-39634",
    "CVE-2021-39698",
    "CVE-2021-39713",
    "CVE-2021-44733",
    "CVE-2021-45485",
    "CVE-2021-45486",
    "CVE-2021-45868",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0492",
    "CVE-2022-0494",
    "CVE-2022-0617",
    "CVE-2022-1011",
    "CVE-2022-1012",
    "CVE-2022-1016",
    "CVE-2022-1353",
    "CVE-2022-1678",
    "CVE-2022-1729",
    "CVE-2022-20008",
    "CVE-2022-20132",
    "CVE-2022-20141",
    "CVE-2022-23960",
    "CVE-2022-24448",
    "CVE-2022-27666",
    "CVE-2022-28388",
    "CVE-2022-28390",
    "CVE-2022-29581",
    "CVE-2022-30594",
    "CVE-2022-32250",
    "CVE-2022-32296"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : kernel (EulerOS-SA-2022-2566)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a
    network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP,
    CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.
    (CVE-2020-24586)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary
    can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP encryption key is periodically renewed. (CVE-2020-24587)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - An issue was discovered in the kernel in NetBSD 7.1. An Access Point (AP) forwards EAPOL frames to other
    clients even though the sender has not yet successfully authenticated to the AP. This might be abused in
    projected Wi-Fi networks to launch denial-of-service attacks against connected clients and makes it easier
    to exploit other vulnerabilities in connected clients. (CVE-2020-26139)

  - An issue was discovered in the ALFA Windows 10 driver 6.1316.1209 for AWUS036H. The WEP, WPA, WPA2, and
    WPA3 implementations accept plaintext frames in a protected Wi-Fi network. An adversary can abuse this to
    inject arbitrary data frames independent of the network configuration. (CVE-2020-26140)

  - An issue was discovered in the ALFA Windows 10 driver 6.1316.1209 for AWUS036H. The Wi-Fi implementation
    does not verify the Message Integrity Check (authenticity) of fragmented TKIP frames. An adversary can
    abuse this to inject and possibly decrypt packets in WPA or WPA2 networks that support the TKIP data-
    confidentiality protocol. (CVE-2020-26141)

  - An issue was discovered in the kernel in OpenBSD 6.6. The WEP, WPA, WPA2, and WPA3 implementations treat
    fragmented frames as full frames. An adversary can abuse this to inject arbitrary network packets,
    independent of the network configuration. (CVE-2020-26142)

  - An issue was discovered in the ALFA Windows 10 driver 1030.36.604 for AWUS036ACH. The WEP, WPA, WPA2, and
    WPA3 implementations accept fragmented plaintext frames in a protected Wi-Fi network. An adversary can
    abuse this to inject arbitrary data frames independent of the network configuration. (CVE-2020-26143)

  - A flaw was found in the Linux kernel, where the WiFi implementations accept plaintext A-MSDU frames as
    long as the first 8 bytes correspond to a valid RFC1042 (ex., LLC/SNAP) header for EAPOL. The highest
    threat from this vulnerability is to integrity. (CVE-2020-26144)

  - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3
    implementations accept second (or subsequent) broadcast fragments even when sent in plaintext and process
    them as full unfragmented frames. An adversary can abuse this to inject arbitrary network packets
    independent of the network configuration. (CVE-2020-26145)

  - A vulnerability was found in Linux kernel, where the WiFi implementation reassemble fragments with non-
    consecutive packet numbers. An adversary can abuse this to exfiltrate selected fragments. This
    vulnerability is exploitable when another device sends fragmented frames and the WEP, CCMP, or GCMP data-
    confidentiality protocol is used. Note that WEP is vulnerable to this attack by design. (CVE-2020-26146)

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References:
    Upstream kernel (CVE-2021-0920)

  - In memzero_explicit of compiler-clang.h, there is a possible bypass of defense in depth due to
    uninitialized data. This could lead to local information disclosure with no additional execution
    privileges needed. User interaction is not needed for exploitation. (CVE-2021-0938)

  - In bpf_skb_change_head of filter.c, there is a possible out of bounds read due to a use after free. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-154177719References:
    Upstream kernel (CVE-2021-0941)

  - A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

  - A denial-of-service (DoS) flaw was identified in the Linux kernel due to an incorrect memory barrier in
    xt_replace_table in net/netfilter/x_tables.c in the netfilter subsystem. (CVE-2021-29650)

  - Improper input validation in the Intel(R) Ethernet ixgbe driver for Linux before version 3.17.3 may allow
    an authenticated user to potentially enable denial of service via local access. (CVE-2021-33098)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because the protection mechanism neglects
    the possibility of uninitialized memory locations on the BPF stack. (CVE-2021-34556)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because a certain preempting store
    operation does not necessarily occur before a store operation that has an attacker-controlled value.
    (CVE-2021-35477)

  - A vulnerability was found in the Linux kernel in versions prior to v5.14-rc1. Missing size validations on
    inbound SCTP packets may allow the kernel to read uninitialized memory. (CVE-2021-3655)

  - A flaw was found in the Linux kernel. A memory leak in the ccp-ops crypto driver can allow attackers to
    cause a denial of service. This vulnerability is similar with the older CVE-2019-18808. The highest threat
    from this vulnerability is to system availability. (CVE-2021-3744)

  - A memory leak flaw was found in the Linux kernel's ccp_run_aes_gcm_cmd() function that allows an attacker
    to cause a denial of service. The vulnerability is similar to the older CVE-2019-18808. The highest threat
    from this vulnerability is to system availability. (CVE-2021-3764)

  - A flaw was found in the Linux SCTP stack. A blind attacker may be able to kill an existing SCTP
    association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and
    the attacker can send packets with spoofed IP addresses. (CVE-2021-3772)

  - net/netfilter/nf_conntrack_standalone.c in the Linux kernel before 5.12.2 allows observation of changes in
    any net namespace because these changes are leaked into all other net namespaces. This is related to the
    NF_SYSCTL_CT_MAX, NF_SYSCTL_CT_EXPECT_MAX, and NF_SYSCTL_CT_BUCKETS sysctls. (CVE-2021-38209)

  - In gre_handle_offloads of ip_gre.c, there is a possible page fault due to an invalid memory access. This
    could lead to local information disclosure with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-150694665References: Upstream kernel (CVE-2021-39633)

  - In fs/eventpoll.c, there is a possible use after free. This could lead to local escalation of privilege
    with no additional execution privileges needed. User interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID: A-204450605References: Upstream kernel (CVE-2021-39634)

  - In aio_poll_complete_work of aio.c, there is a possible memory corruption due to a use after free. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation. (CVE-2021-39698)

  - A use-after-free flaw was found in the Linux kernel's network scheduling subsystem due to a race
    condition.This flaw allows a local user to cause a denial of service (memory corruption or crash) or
    privilege escalation. (CVE-2021-39713)

  - A memory leak flaw in the Linux kernel's hugetlbfs memory usage was found in the way the user maps some
    regions of memory twice using shmget() which are aligned to PUD alignment with the fault of some of the
    memory pages. A local user could use this flaw to get unauthorized access to some data. (CVE-2021-4002)

  - A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that
    allows local users to create files for the XFS file-system with an unintended group ownership and with
    group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a
    certain group and is writable by a user who is not a member of this group. This can lead to excessive
    permissions granted in case when they should not. This vulnerability is similar to the previous
    CVE-2018-13405 and adds the missed fix for the XFS. (CVE-2021-4037)

  - A read-after-free memory flaw was found in the Linux kernel s garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges o
    (CVE-2021-4083)

  - A flaw memory leak in the Linux kernel's eBPF for the Simulated networking device driver in the way user
    uses BPF for the device such that function nsim_map_alloc_elem being called. A local user could use this
    flaw to get unauthorized access to some data. (CVE-2021-4135)

  - An out of memory bounds write flaw (1 or 2 bytes of memory) in the Linux kernel NFS subsystem was found in
    the way users use mirroring (replication of files with NFS). A user, having access to the NFS mount, could
    potentially use this flaw to crash the system or escalate privileges on the system. (CVE-2021-4157)

  - A vulnerability was found in the Linux kernel's EBPF verifier when handling internal data structures.
    Internal memory locations could be returned to userspace. A local attacker with the permissions to insert
    eBPF code to the kernel can use this to leak internal kernel memory details defeating some of the exploit
    mitigations in place for the kernel. (CVE-2021-4159)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - In the IPv6 implementation in the Linux kernel before 5.13.3, net/ipv6/output_core.c has an information
    leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based
    attackers can typically choose among many IPv6 source addresses. (CVE-2021-45485)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

  - In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota
    tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a
    corrupted quota file. (CVE-2021-45868)

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - A flaw use after free in the Linux kernel FUSE filesystem was found in the way user triggers write(). A
    local user could use this flaw to get some unauthorized access to some data from the FUSE filesystem and
    as result potentially privilege escalation too. (CVE-2022-1011)

  - Due to the small table perturb size, a memory leak flaw was found in the Linux kernel's TCP source port
    generation algorithm in the net/ipv4/tcp.c function. This flaw allows an attacker to leak information and
    may cause a denial of service. (CVE-2022-1012)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain,which can cause a use-
    after-free.This issue needs to handle return with proper preconditions,as it can lead to a kernel
    information leak problem caused by a local,unprivileged attacker. (CVE-2022-1016)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel.This flaw
    allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a leak of
    internal kernel information. (CVE-2022-1353)

  - An issue was discovered in the Linux Kernel from 4.18 to 4.19, an improper update of sock reference in TCP
    pacing can lead to memory/netns leak, which can be used by remote clients. (CVE-2022-1678)

  - Kernel-headers includes the C header files that specify the interfacebetween the Linux kernel and
    userspace libraries and programs.  Theheader files define structures and constants that are needed
    forbuilding most standard programs and are also needed for rebuilding theglibc package. (CVE-2022-1729)

  - In mmc_blk_read_single of block.c, there is a possible way to read kernel heap memory due to uninitialized
    data. This could lead to local information disclosure if reading from an SD card that triggers errors,
    with no additional execution privileges needed. User interaction is not needed for exploitation.
    (CVE-2022-20008)

  - In lg_probe and related functions of hid-lg.c and other USB HID files, there is a possible out of bounds
    read due to improper input validation. This could lead to local information disclosure if a malicious USB
    HID device were plugged in, with no additional execution privileges needed. User interaction is not needed
    for exploitation. (CVE-2022-20132)

  - In ip_check_mc_rcu of igmp.c, there is a possible use after free due to improper locking. This could lead
    to local escalation of privilege when opening and closing inet sockets with no additional execution
    privileges needed. User interaction is not needed for exploitation. (CVE-2022-20141)

  - Certain Arm Cortex and Neoverse processors through 2022-03-08 do not properly restrict cache speculation,
    aka Spectre-BHB.An attacker can leverage the shared branch history in the Branch History Buffer (BHB) to
    influence mispredicted branches.Then, cache allocation can allow the attacker to obtain sensitive
    information. (CVE-2022-23960)

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. (CVE-2022-32296)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2566
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c3963be");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4157");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bpftool-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "kernel-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "kernel-devel-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "kernel-headers-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "kernel-tools-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "perf-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "python-perf-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8",
  "python3-perf-4.19.36-vhulk1907.1.0.h1252.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
