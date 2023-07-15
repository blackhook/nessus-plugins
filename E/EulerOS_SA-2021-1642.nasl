#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147690);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2020-0404",
    "CVE-2020-0427",
    "CVE-2020-0431",
    "CVE-2020-0432",
    "CVE-2020-0466",
    "CVE-2020-8694",
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-14314",
    "CVE-2020-14385",
    "CVE-2020-14386",
    "CVE-2020-15437",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25641",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25668",
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-25705",
    "CVE-2020-26088",
    "CVE-2020-27068",
    "CVE-2020-27673",
    "CVE-2020-27675",
    "CVE-2020-27777",
    "CVE-2020-27786",
    "CVE-2020-27830",
    "CVE-2020-28915",
    "CVE-2020-28941",
    "CVE-2020-28974",
    "CVE-2020-29368",
    "CVE-2020-29371",
    "CVE-2020-29660",
    "CVE-2020-29661"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"EulerOS Virtualization 2.9.0 : kernel (EulerOS-SA-2021-1642)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - In create_pinctrl of core.c, there is a possible out of
    bounds read due to a use after free. This could lead to
    local information disclosure with no additional
    execution privileges needed.(CVE-2020-0427)

  - NULL-ptr deref in the spk_ttyio_receive_buf2() function
    in spk_ttyio.c.(CVE-2020-27830)

  - In do_epoll_ctl and ep_loop_check_proc of eventpoll.c,
    there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege
    with no additional execution privileges
    needed.(CVE-2020-0466)

  - In the nl80211_policy policy of nl80211.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with System execution privileges
    needed.(CVE-2020-27068)

  - use-after-free read in sunkbd_reinit in
    drivers/input/keyboard/sunkbd.c.(CVE-2020-25669)

  - A flaw was found in the Linux kernels implementation of
    MIDI, where an attacker with a local account and the
    permissions to issue an ioctl commands to midi devices,
    could trigger a use-after-free. A write to this
    specific memory while freed and before use could cause
    the flow of execution to change and possibly allow for
    memory corruption or privilege
    escalation.(CVE-2020-27786)

  - An issue was discovered in romfs_dev_read in
    fs/romfs/storage.c in the Linux kernel before 5.8.4.
    Uninitialized memory leaks to userspace, aka
    CID-bcf85fcedfdd.(CVE-2020-29371)

  - A slab-out-of-bounds read in fbcon in the Linux kernel
    before 5.9.7 could be used by local attackers to read
    privileged information or potentially crash the kernel,
    aka CID-3c4e0dff2095. This occurs because
    KD_FONT_OP_COPY in drivers/tty/vt/vt.c can be used for
    manipulations such as font height.(CVE-2020-28974)

  - A locking inconsistency issue was discovered in the tty
    subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    allow a read-after-free attack against TIOCGSID, aka
    CID-c8bcd9c5be24.(CVE-2020-29660)

  - A locking issue was discovered in the tty subsystem of
    the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free
    attack against TIOCSPGRP, aka
    CID-54ffccbf053b.(CVE-2020-29661)

  - An issue was discovered in
    drivers/accessibility/speakup/spk_ttyio.c in the Linux
    kernel through 5.9.9. Local attackers on systems with
    the speakup driver could cause a local denial of
    service attack, aka CID-d41227544427. This occurs
    because of an invalid free when the line discipline is
    used more than once.(CVE-2020-28941)

  - A buffer over-read (at the framebuffer layer) in the
    fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka
    CID-6735b4632def.(CVE-2020-28915)

  - A flaw in the way reply ICMP packets are limited in the
    Linux kernel functionality was found that allows to
    quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypassing source
    port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly
    integrity, because software that relies on UDP source
    port randomization are indirectly affected as well.
    Kernel versions before 5.10 may be vulnerable to this
    issue.(CVE-2020-25705)

  - race condition in fg_console can lead to use-after-free
    in con_font_op.(CVE-2020-25668)

  - The Linux kernel before version 5.8 is vulnerable to a
    NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init
    _ports() that allows local users to cause a denial of
    service by using the p->serial_in pointer which
    uninitialized.(CVE-2020-15437)

  - An issue was discovered in the Linux kernel through
    5.9.1, as used with Xen through 4.14.x. Guest OS users
    can cause a denial of service (host OS hang) via a high
    rate of events to dom0, aka
    CID-e99502f76271.(CVE-2020-27673)

  - An issue was discovered in __split_huge_pmd in
    mm/huge_memory.c in the Linux kernel before 5.7.5. The
    copy-on-write implementation can grant unintended write
    access because of a race condition in a THP mapcount
    check, aka CID-c444eb564fb1.(CVE-2020-29368)

  - An issue was discovered in the Linux kernel through
    5.9.1, as used with Xen through 4.14.x.
    drivers/xen/events/events_base.c allows event-channel
    removal during the event-handling loop (a race
    condition). This can cause a use-after-free or NULL
    pointer dereference, as demonstrated by a dom0 crash
    via events for an in-reconfiguration paravirtualized
    device, aka CID-073d0552ead5.(CVE-2020-27675)

  - A flaw was found in the way RTAS handled memory
    accesses in userspace to kernel communication. On a
    locked down (usually due to Secure Boot) guest system
    running on top of PowerVM or KVM hypervisors (pseries
    platform) a root like local user could use this flaw to
    further increase their privileges to that of a running
    kernel.(CVE-2020-27777)

  - There is a memory leak in
    perf_event_parse_addr_filter.(CVE-2020-25704)

  - Insufficient access control in the Linux kernel driver
    for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via
    local access.(CVE-2020-8694)

  - A flaw was found in the Linux kernel. A use-after-free
    was found in the way the console subsystem was using
    ioctls KDGKBSENT and KDSKBSENT. A local user could use
    this flaw to get read memory access out of bounds. The
    highest threat from this vulnerability is to data
    confidentiality.(CVE-2020-25656)

  - In kbd_keycode of keyboard.c, there is a possible out
    of bounds write due to a missing bounds check. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-144161459(CVE-2020-0431)

  - A flaw was found in the HDLC_PPP module of the Linux
    kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input
    validation in the ppp_cp_parse_cr function which can
    cause the system to crash or cause a denial of service.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25643)

  - A flaw was found in the Linux kernel in versions before
    5.9-rc7. Traffic between two Geneve endpoints may be
    unencrypted when IPsec is configured to encrypt traffic
    for the specific UDP port used by the GENEVE tunnel
    allowing anyone between the two endpoints to read the
    traffic unencrypted. The main threat from this
    vulnerability is to data
    confidentiality.(CVE-2020-25645)

  - An information leak flaw was found in the way the Linux
    kernel's Bluetooth stack implementation handled
    initialization of stack memory when handling certain
    AMP packets. A remote attacker in adjacent range could
    use this flaw to leak small portions of stack memory on
    the system by sending a specially crafted AMP packets.
    The highest threat from this vulnerability is to data
    confidentiality.(CVE-2020-12352)

  - A flaw was found in the way the Linux kernel Bluetooth
    implementation handled L2CAP packets with A2MP CID. A
    remote attacker in adjacent range could use this flaw
    to crash the system causing denial of service or
    potentially execute arbitrary code on the system by
    sending a specially crafted L2CAP packet. The highest
    threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-12351)

  - A missing CAP_NET_RAW check in NFC socket creation in
    net/nfc/rawsock.c in the Linux kernel before 5.8.2
    could be used by local attackers to create raw sockets,
    bypassing security mechanisms, aka
    CID-26896f01467a.(CVE-2020-26088)

  - A flaw was found in the Linux kernel's implementation
    of biovecs in versions before 5.9-rc7. A zero-length
    biovec request issued by the block subsystem could
    cause the kernel to enter an infinite loop, causing a
    denial of service. This flaw allows a local attacker
    with basic privileges to issue requests to a block
    device, resulting in a denial of service. The highest
    threat from this vulnerability is to system
    availability.(CVE-2020-25641)

  - In skb_to_mamac of networking.c, there is a possible
    out of bounds write due to an integer overflow. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-143560807(CVE-2020-0432)

  - A TOCTOU mismatch in the NFS client code in the Linux
    kernel before 5.8.3 could be used by local attackers to
    corrupt memory or possibly have unspecified other
    impact because a size check is in fs/ nfs/ nfs4proc.c
    instead of fs/ nfs/ nfs4xdr.c, aka
    CID-b4487b935452..(CVE-2020-25212)

  - A flaw was found in the Linux kernel before 5.9-rc4. A
    failure of the file system metadata validator in XFS
    can cause an inode with a valid, user-creatable
    extended attribute to be flagged as corrupt. This can
    lead to the filesystem being shutdown, or otherwise
    rendered inaccessible until it is remounted, leading to
    a denial of service. The highest threat from this
    vulnerability is to system
    availability.(CVE-2020-14385)

  - In uvc_scan_chain_forward of uvc_driver.c, there is a
    possible linked list corruption due to an unusual root
    cause. This could lead to local escalation of privilege
    in the kernel with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-111893654References: Upstream
    kernel(CVE-2020-0404)

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

  - A memory out-of-bounds read flaw was found in the Linux
    kernel before 5.9-rc2 with the ext3/ext4 file system,
    in the way it accesses a directory with broken
    indexing. This flaw allows a local user to crash the
    system if the directory exists. The highest threat from
    this vulnerability is to system
    availability.(CVE-2020-14314)

  - A flaw was found in the Linux kernel before 5.9-rc4.
    Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest
    threat from this vulnerability is to data
    confidentiality and integrity.(CVE-2020-14386)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1642
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fbd2c64");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-4.18.0-147.5.1.2.h314.eulerosv2r9",
        "kernel-tools-4.18.0-147.5.1.2.h314.eulerosv2r9",
        "kernel-tools-libs-4.18.0-147.5.1.2.h314.eulerosv2r9",
        "python3-perf-4.18.0-147.5.1.2.h314.eulerosv2r9"];

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
