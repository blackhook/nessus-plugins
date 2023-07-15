#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144731);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2015-7837",
    "CVE-2019-0145",
    "CVE-2019-0147",
    "CVE-2019-18282",
    "CVE-2019-18805",
    "CVE-2019-20934",
    "CVE-2020-0404",
    "CVE-2020-0431",
    "CVE-2020-0432",
    "CVE-2020-10690",
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-14314",
    "CVE-2020-14351",
    "CVE-2020-14385",
    "CVE-2020-14386",
    "CVE-2020-14390",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-24394",
    "CVE-2020-24490",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25641",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25704",
    "CVE-2020-26088",
    "CVE-2020-27777",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29370",
    "CVE-2020-29371",
    "CVE-2020-29374"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2021-1039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc. Security Fix(es):In uvc_scan_chain_forward
    of uvc_driver.c, there is a possible linked list
    corruption due to an unusual root cause. This could
    lead to local escalation of privilege in the kernel
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-111893654References: Upstream kernel.(CVE-2020-0404)A
    flaw was found in the Linux kernel in versions from
    2.2.3 through 5.9.rc5. When changing screen size, an
    out-of-bounds memory write can occur leading to memory
    corruption or a denial of service. This highest threat
    from this vulnerability is to system
    availability.(CVE-2020-14390)A TOCTOU mismatch in the
    NFS client code in the Linux kernel before 5.8.3 could
    be used by local attackers to corrupt memory or
    possibly have unspecified other impact because a size
    check is in fs4proc.c instead of fsfs4xdr.c, aka
    CID-b4487b935452.(CVE-2020-25212)A flaw was found in
    the Linux kernel before 5.9-rc4. A failure of the file
    system metadata validator in XFS can cause an inode
    with a valid, user-creatable extended attribute to be
    flagged as corrupt. This can lead to the filesystem
    being shutdown, or otherwise rendered inaccessible
    until it is remounted, leading to a denial of service.
    The highest threat from this vulnerability is to system
    availability.(CVE-2020-14385)In the Linux kernel before
    5.7.8, fsfsd/vfs.c (in the NFS server) can set
    incorrect permissions on new filesystem objects when
    the filesystem lacks ACL support, aka CID-22cf8419f131.
    This occurs because the current umask is not
    considered.(CVE-2020-24394)The rbd block device driver
    in drivers/block/rbd.c in the Linux kernel through
    5.8.9 used incomplete permission checking for access to
    rbd devices, which could be leveraged by local
    attackers to map or unmap rbd block devices, aka
    CID-f44d04e696fe.(CVE-2020-25284)An issue was
    discovered in net/ipv4/sysctl_net_ipv4.c in the Linux
    kernel before 5.0.11. There is a net/ipv4/tcp_input.c
    signed integer overflow in tcp_ack_update_rtt() when
    userspace writes a very large integer to /proc/sys
    et/ipv4/tcp_min_rtt_wlen, leading to a denial of
    service or possibly unspecified other impact, aka
    CID-19fad20d15a6.(CVE-2019-18805)Insufficient input
    validation in i40e driver for Intel(R) Ethernet 700
    Series Controllers versions before 7.0 may allow an
    authenticated user to potentially enable a denial of
    service via local access.(CVE-2019-0147)Buffer overflow
    in i40e driver for Intel(R) Ethernet 700 Series
    Controllers versions before 7.0 may allow an
    authenticated user to potentially enable an escalation
    of privilege via local access.(CVE-2020-0145)A race
    condition between hugetlb sysctl handlers in
    mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL
    pointer dereference, or possibly have unspecified other
    impact, aka CID-17743798d812.(CVE-2020-25285)A memory
    out-of-bounds read flaw was found in the Linux kernel
    before 5.9-rc2 with the ext3/ext4 file system, in the
    way it accesses a directory with broken indexing. This
    flaw allows a local user to crash the system if the
    directory exists. The highest threat from this
    vulnerability is to system
    availability.(CVE-2020-14314)A missing CAP_NET_RAW
    check in NFC socket creation in net fc/rawsock.c in the
    Linux kernel before 5.8.2 could be used by local
    attackers to create raw sockets, bypassing security
    mechanisms, aka CID-26896f01467a.(CVE-2020-26088)A flaw
    was found in the HDLC_PPP module of the Linux kernel in
    versions before 5.9-rc7. Memory corruption and a read
    overflow is caused by improper input validation in the
    ppp_cp_parse_cr function which can cause the system to
    crash or cause a denial of service. The highest threat
    from this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-25643)The Linux kernel, as used
    in Red Hat Enterprise Linux 7, kernel-rt, and
    Enterprise MRG 2 and when booted with UEFI Secure Boot
    enabled, allows local users to bypass intended
    securelevel/secureboot restrictions by leveraging
    improper handling of secure_boot flag across kexec
    reboot.(CVE-2015-7837)A flaw was found in the Linux
    kernel's implementation of biovecs in versions before
    5.9-rc7. A zero-length biovec request issued by the
    block subsystem could cause the kernel to enter an
    infinite loop, causing a denial of service. This flaw
    allows a local attacker with basic privileges to issue
    requests to a block device, resulting in a denial of
    service. The highest threat from this vulnerability is
    to system availability.(CVE-2020-25641)A flaw was found
    in the Linux kernel before 5.9-rc4. Memory corruption
    can be exploited to gain root privileges from
    unprivileged processes. The highest threat from this
    vulnerability is to data confidentiality and
    integrity.(CVE-2020-14386)A flaw was found in the Linux
    kernel in versions before 5.9-rc7. Traffic between two
    Geneve endpoints may be unencrypted when IPsec is
    configured to encrypt traffic for the specific UDP port
    used by the GENEVE tunnel allowing anyone between the
    two endpoints to read the traffic unencrypted. The main
    threat from this vulnerability is to data
    confidentiality.(CVE-2020-25645)perf: Fix race in
    perf_mmap_close function.(CVE-2020-14351)An information
    leak flaw was found in the way the Linux kernel's
    Bluetooth stack implementation handled initialization
    of stack memory when handling certain AMP packets. A
    remote attacker in adjacent range could use this flaw
    to leak small portions of stack memory on the system by
    sending a specially crafted AMP packets. The highest
    threat from this vulnerability is to data
    confidentiality.(CVE-2020-12352)A flaw was found in the
    way the Linux kernel Bluetooth implementation handled
    L2CAP packets with A2MP CID. A remote attacker in
    adjacent range could use this flaw to crash the system
    causing denial of service or potentially execute
    arbitrary code on the system by sending a specially
    crafted L2CAP packet. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as system availability.(CVE-2020-12351)A heap
    buffer overflow flaw was found in the way the Linux
    kernel's Bluetooth implementation processed extended
    advertising report events. This flaw allows a remote
    attacker in an adjacent range to crash the system,
    causing a denial of service or to potentially execute
    arbitrary code on the system by sending a specially
    crafted Bluetooth packet. The highest threat from this
    vulnerability is to confidentiality, integrity, as well
    as system availability.(CVE-2020-24490)** RESERVED **
    This candidate has been reserved by an organization or
    individual that will use it when announcing a new
    security problem. When the candidate has been
    publicized, the details for this candidate will be
    provided.(CVE-2020-25656)In skb_to_mamac of
    networking.c, there is a possible out of bounds write
    due to an integer overflow. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-143560807(CVE-2020-0432)A
    slab-out-of-bounds read in fbcon in the Linux kernel
    before 5.9.7 could be used by local attackers to read
    privileged information or potentially crash the kernel,
    aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for
    manipulations such as font height.(CVE-2020-28974)A
    flaw memory leak in the Linux kernel performance
    monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this
    flaw to starve the resources causing denial of
    service.(CVE-2020-25704)A buffer over-read (at the
    framebuffer layer) in the fbcon code in the Linux
    kernel before 5.8.15 could be used by local attackers
    to read kernel memory, aka
    CID-6735b4632def.(CVE-2020-28915)There is a
    use-after-free problem seen due to a race condition
    between the release of ptp_clock and cdev while
    resource deallocation. When a (high privileged) process
    allocates a ptp device file (like /dev/ptpX) and
    voluntarily goes to sleep. During this time if the
    underlying device is removed, it can cause an
    exploitable condition as the process wakes up to
    terminate and clean all attached files. The system
    crashes due to the cdev structure being invalid (as
    already freed) which is pointed to by the
    inode.(CVE-2020-10690)A device tracking vulnerability
    was found in the flow_dissector feature in the Linux
    kernel. This flaw occurs because the auto flowlabel of
    the UDP IPv6 packet relies on a 32-bit hashmd value as
    a secret, and jhash (instead of siphash) is used. The
    hashmd value remains the same starting from boot time
    and can be inferred by an
    attacker.(CVE-2019-18282)Use-after-free vulnerability
    in fs/block_dev.c in the Linux kernel before 5.8 allows
    local users to gain privileges or cause a denial of
    service by leveraging improper access to a certain
    error field.(CVE-2020-15436)The Linux kernel before
    version 5.8 is vulnerable to a NULL pointer dereference
    in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init
    _ports() that allows local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized.(CVE-2020-15437)An issue was discovered
    in kmem_cache_alloc_bulk in mm/slub.c in the Linux
    kernel before 5.5.11. The slowpath lacks the required
    TID increment, aka CID-fd4d9c7d0c71.(CVE-2020-29370)An
    issue was discovered in the Linux kernel before 5.2.6.
    On NUMA systems, the Linux fair scheduler has a
    use-after-free in show_numa_stats() because NUMA fault
    statistics are inappropriately freed, aka
    CID-16d51a590a8c.(CVE-2019-20934)An issue was
    discovered in romfs_dev_read in fs/romfs/storage.c in
    the Linux kernel before 5.8.4. Uninitialized memory
    leaks to userspace, aka
    CID-bcf85fcedfdd.(CVE-2020-29371)An issue was
    discovered in the Linux kernel before 5.7.3, related to
    mm/gup.c and mm/huge_memory.c. The get_user_pages (aka
    gup) implementation, when used for a copy-on-write
    page, does not properly consider the semantics of read
    operations and therefore can grant unintended write
    access, aka CID-17839856fd58.(CVE-2020-29374)A flaw was
    found in the way RTAS handled memory accesses in
    userspace to kernel communication. On a locked down
    (usually due to Secure Boot) guest system running on
    top of PowerVM or KVM hypervisors (pseries platform) a
    root like local user could use this flaw to further
    increase their privileges to that of a running
    kernel.(CVE-2020-27777)In kbd_keycode of keyboard.c,
    there is a possible out of bounds write due to a
    missing bounds check. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-144161459(CVE-2020-0431)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1039
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92f0c0ab");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h906",
        "kernel-devel-4.19.36-vhulk1907.1.0.h906",
        "kernel-headers-4.19.36-vhulk1907.1.0.h906",
        "kernel-tools-4.19.36-vhulk1907.1.0.h906",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h906",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h906"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
