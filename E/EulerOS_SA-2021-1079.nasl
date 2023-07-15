#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145201);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/22");

  script_cve_id(
    "CVE-2019-20934",
    "CVE-2019-3701",
    "CVE-2019-9456",
    "CVE-2019-9458",
    "CVE-2020-0305",
    "CVE-2020-0431",
    "CVE-2020-0433",
    "CVE-2020-10773",
    "CVE-2020-12114",
    "CVE-2020-12352",
    "CVE-2020-14305",
    "CVE-2020-14314",
    "CVE-2020-14351",
    "CVE-2020-14386",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25211",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29370",
    "CVE-2020-29371",
    "CVE-2020-29660",
    "CVE-2020-29661"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2021-1079)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A stack information leak flaw was found in s390/s390x
    in the Linux kernel's memory manager functionality,
    where it incorrectly writes to the
    /proc/sys/vm/cmm_timeout file. This flaw allows a local
    user to see the kernel data.(CVE-2020-10773)

  - In the Android kernel in the video driver there is a
    use after free due to a race condition. This could lead
    to local escalation of privilege with no additional
    execution privileges needed. User interaction is not
    needed for exploitation.(CVE-2019-9458)

  - An issue was discovered in the Linux kernel before
    5.2.6. On NUMA systems, the Linux fair scheduler has a
    use-after-free in show_numa_stats() because NUMA fault
    statistics are inappropriately freed, aka
    CID-16d51a590a8c.(CVE-2019-20934)

  - A locking inconsistency issue was discovered in the tty
    subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    allow a read-after-free attack against TIOCGSID, aka
    CID-c8bcd9c5be24.(CVE-2020-29660)

  - An out-of-bounds memory write flaw was found in how the
    Linux kernel's Voice Over IP H.323 connection tracking
    functionality handled connections on ipv6 port 1720.
    This flaw allows an unauthenticated remote user to
    crash the system, causing a denial of service. The
    highest threat from this vulnerability is to
    confidentiality, integrity, as well as system
    availability.(CVE-2020-14305)

  - A locking issue was discovered in the tty subsystem of
    the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free
    attack against TIOCSPGRP, aka
    CID-54ffccbf053b.(CVE-2020-29661)

  - An issue was discovered in romfs_dev_read in
    fs/romfs/storage.c in the Linux kernel before 5.8.4.
    Uninitialized memory leaks to userspace, aka
    CID-bcf85fcedfdd.(CVE-2020-29371)

  - Use-after-free vulnerability in fs/block_dev.c in the
    Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging
    improper access to a certain error
    field.(CVE-2020-15436)

  - The Linux kernel before version 5.8 is vulnerable to a
    NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init
    _ports() that allows local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized.(CVE-2020-15437)

  - An issue was discovered in kmem_cache_alloc_bulk in
    mm/slub.c in the Linux kernel before 5.5.11. The
    slowpath lacks the required TID increment, aka
    CID-fd4d9c7d0c71.(CVE-2020-29370)

  - A flaw was found in the Linux kernel. A use-after-free
    memory flaw was found in the perf subsystem allowing a
    local attacker with permission to monitor perf events
    to corrupt memory and possibly escalate privileges. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-14351)

  - A buffer over-read (at the framebuffer layer) in the
    fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka
    CID-6735b4632def.(CVE-2020-28915)

  - A slab-out-of-bounds read in fbcon in the Linux kernel
    before 5.9.7 could be used by local attackers to read
    privileged information or potentially crash the kernel,
    aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for
    manipulations such as font height.(CVE-2020-28974)

  - Improper access control in BlueZ may allow an
    unauthenticated user to potentially enable information
    disclosure via adjacent access.(CVE-2020-12352)

  - In cdev_get of char_dev.c, there is a possible
    use-after-free due to a race condition. This could lead
    to local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions:
    Android-10Android ID: A-153467744(CVE-2020-0305)

  - A flaw was found in the HDLC_PPP module of the Linux
    kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input
    validation in the ppp_cp_parse_cr function which can
    cause the system to crash or cause a denial of service.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25643)

  - An issue was discovered in can_can_gw_rcv in
    net/can/gw.c in the Linux kernel through 4.19.13. The
    CAN frame modification rules allow bitwise logical
    operations that can be also applied to the can_dlc
    field. The privileged user 'root' with CAP_NET_ADMIN
    can create a CAN frame modification rule that makes the
    data length code a higher value than the available CAN
    frame data size. In combination with a configured
    checksum calculation where the result is stored
    relatively to the end of the data (e.g.
    cgw_csum_xor_rel) the tail of the skb (e.g. frag_list
    pointer in skb_shared_info) can be rewritten which
    finally can cause a system crash. Because of a missing
    check, the CAN drivers may write arbitrary content
    beyond the data registers in the CAN controller's I/O
    memory when processing can-gw manipulated outgoing
    frames.(CVE-2019-3701)

  - In the Android kernel in Pixel C USB monitor driver
    there is a possible OOB write due to a missing bounds
    check. This could lead to local escalation of privilege
    with System execution privileges needed. User
    interaction is not needed for
    exploitation.(CVE-2019-9456)

  - A pivot_root race condition in fs/ namespace.c in the
    Linux kernel 4.4.x before 4.4.221, 4.9.x before
    4.9.221, 4.14.x before 4.14.178, 4.19.x before
    4.19.119, and 5.x before 5.3 allows local users to
    cause a denial of service (panic) by corrupting a
    mountpoint reference counter.(CVE-2020-12114)

  - A flaw was found in the Linux kernel in versions before
    5.9-rc7. Traffic between two Geneve endpoints may be
    unencrypted when IPsec is configured to encrypt traffic
    for the specific UDP port used by the GENEVE tunnel
    allowing anyone between the two endpoints to read the
    traffic unencrypted. The main threat from this
    vulnerability is to data
    confidentiality.(CVE-2020-25645)

  - In kbd_keycode of keyboard.c, there is a possible out
    of bounds write due to a missing bounds check. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-144161459(CVE-2020-0431)

  - In blk_mq_queue_tag_busy_iter of blk-mq-tag.c, there is
    a possible use after free due to improper locking. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-151939299(CVE-2020-0433)

  - In the Linux kernel through 5.8.7, local attackers able
    to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering
    use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/ netfilter/
    nf_conntrack_netlink.c, aka
    CID-1cc5ef91d2ff.(CVE-2020-25211)

  - A memory out-of-bounds read flaw was found in the Linux
    kernel before 5.9-rc2 with the ext3/ext4 file system,
    in the way it accesses a directory with broken
    indexing. This flaw allows a local user to crash the
    system if the directory exists. The highest threat from
    this vulnerability is to system
    availability.(CVE-2020-14314)

  - A TOCTOU mismatch in the NFS client code in the Linux
    kernel before 5.8.3 could be used by local attackers to
    corrupt memory or possibly have unspecified other
    impact because a size check is in fs/ nfs/ nfs4proc.c
    instead of fs/ nfs/ nfs4xdr.c, aka
    CID-b4487b935452.(CVE-2020-25212)

  - The rbd block device driver in drivers/block/rbd.c in
    the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which
    could be leveraged by local attackers to map or unmap
    rbd block devices, aka
    CID-f44d04e696fe.(CVE-2020-25284)

  - A race condition between hugetlb sysctl handlers in
    mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL
    pointer dereference, or possibly have unspecified other
    impact, aka CID-17743798d812.(CVE-2020-25285)

  - A flaw was found in the Linux kernel before 5.9-rc4.
    Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest
    threat from this vulnerability is to data
    confidentiality and integrity.(CVE-2020-14386)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1079
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83f9eb52");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h296",
        "kernel-debuginfo-3.10.0-514.44.5.10.h296",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h296",
        "kernel-devel-3.10.0-514.44.5.10.h296",
        "kernel-headers-3.10.0-514.44.5.10.h296",
        "kernel-tools-3.10.0-514.44.5.10.h296",
        "kernel-tools-libs-3.10.0-514.44.5.10.h296",
        "perf-3.10.0-514.44.5.10.h296",
        "python-perf-3.10.0-514.44.5.10.h296"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
