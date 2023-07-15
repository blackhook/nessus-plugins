#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140917);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2014-8181",
    "CVE-2019-19447",
    "CVE-2019-20636",
    "CVE-2019-20810",
    "CVE-2019-20811",
    "CVE-2019-20812",
    "CVE-2020-0066",
    "CVE-2020-10720",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-10942",
    "CVE-2020-11494",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-12888",
    "CVE-2020-13143",
    "CVE-2020-13974",
    "CVE-2020-14331",
    "CVE-2020-15393",
    "CVE-2020-16166"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2020-2150)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The Linux kernel through 5.7.11 allows remote attackers
    to make observations that help to obtain sensitive
    information about the internal state of the network
    RNG, aka CID-f227e3ec3b5c. This is related to
    drivers/char/random.c and
    kernel/time/timer.c.(CVE-2020-16166)

  - A flaw was found in the Linux kernel's implementation
    of the invert video code on VGA consoles when a local
    attacker attempts to resize the console, calling an
    ioctl VT_RESIZE, which causes an out-of-bounds write to
    occur. This flaw allows a local user with access to the
    VGA console to crash the system, potentially escalating
    their privileges on the system. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2020-14331)

  - A buffer over-read flaw was found in RH kernel versions
    before 5.0 in crypto_authenc_extractkeys in
    crypto/authenc.c in the IPsec Cryptographic algorithm's
    module, authenc. When a payload longer than 4 bytes,
    and is not following 4-byte alignment boundary
    guidelines, it causes a buffer over-read threat,
    leading to a system crash. This flaw allows a local
    attacker with user privileges to cause a denial of
    service.(CVE-2020-10769)

  - An issue was discovered in the Linux kernel through
    5.7.1. drivers/tty/vt/keyboard.c has an integer
    overflow if k_ascii is called several times in a row,
    aka CID-b86dab054059. NOTE: Members in the community
    argue that the integer overflow does not lead to a
    security issue in this case.(CVE-2020-13974)

  - In the Linux kernel through 5.7.6, usbtest_disconnect
    in drivers/usb/misc/usbtest.c has a memory leak, aka
    CID-28ebeb8db770.(CVE-2020-15393)

  - The VFIO PCI driver in the Linux kernel through 5.6.13
    mishandles attempts to access disabled memory
    space.(CVE-2020-12888)

  - go7007_snd_init in
    drivers/media/usb/go7007/snd-go7007.c in the Linux
    kernel before 5.6 does not call snd_card_free for a
    failure path, which causes a memory leak, aka
    CID-9453264ef586.(CVE-2019-20810)

  - An issue was discovered in the Linux kernel before
    5.0.6. In rx_queue_add_kobject() and
    netdev_queue_add_kobject() in net/core/net-sysfs.c, a
    reference count is mishandled, aka
    CID-a3e23f719f5c.(CVE-2019-20811)

  - An issue was discovered in the Linux kernel before
    5.4.7. The prb_calc_retire_blk_tmo() function in
    net/packet/af_packet.c can result in a denial of
    service (CPU consumption and soft lockup) in a certain
    failure case involving TPACKET_V3, aka
    CID-b43d1f9f7067.(CVE-2019-20812)

  - A flaw was found in the Linux kernel's implementation
    of Userspace core dumps. This flaw allows an attacker
    with a local account to crash a trivial program and
    exfiltrate private kernel data.(CVE-2020-10732)

  - A flaw was found in the Linux kernels SELinux LSM hook
    implementation before version 5.7, where it incorrectly
    assumed that an skb would only contain a single netlink
    message. The hook would incorrectly only validate the
    first netlink message in the skb and allow or deny the
    rest of the messages within the skb with the granted
    permission without further processing.(CVE-2020-10751)

  - gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)

  - A signal access-control issue was discovered in the
    Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32
    bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process
    can send an arbitrary signal to a parent process in a
    different security domain. Exploitation limitations
    include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where
    signals to a parent process present a substantial
    operational threat.(CVE-2020-12826)

  - The __mptctl_ioctl function in
    drivers/message/fusion/mptctl.c in the Linux kernel
    before 5.4.14 allows local users to hold an incorrect
    lock during the ioctl operation and trigger a race
    condition, i.e., a 'double fetch' vulnerability, aka
    CID-28d76df18f0a. NOTE: the vendor states 'The security
    impact of this bug is not as bad as it could have been
    because these operations are all privileged and root
    already has enormous destructive
    power.'(CVE-2020-12652)

  - An issue was found in Linux kernel before 5.5.4. The
    mwifiex_cmd_append_vsie_tlv() function in
    drivers/net/wireless/marvell/mwifiex/scan.c allows
    local users to gain privileges or cause a denial of
    service because of an incorrect memcpy and buffer
    overflow, aka CID-b70261a288ea.(CVE-2020-12653)

  - An issue was found in Linux kernel before 5.5.4.
    mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a
    remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka
    CID-3a9b153c5591.(CVE-2020-12654)

  - An issue was discovered in xfs_agf_verify in
    fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through
    5.6.10. Attackers may trigger a sync of excessive
    duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767.(CVE-2020-12655)

  - A flaw was found in the Linux kernel's implementation
    of GRO in versions before 5.2. This flaw allows an
    attacker with local access to crash the
    system.(CVE-2020-10720)

  - An issue was discovered in the Linux kernel through
    5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka
    CID-83c6f2390040.(CVE-2020-12770)

  - In the Linux kernel before 5.4.12,
    drivers/input/input.c has out-of-bounds writes via a
    crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)

  - An issue was discovered in the stv06xx subsystem in the
    Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)

  - In the netlink driver, there is a possible out of
    bounds write due to a race condition. This could lead
    to local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-65025077(CVE-2020-0066)

  - In the Linux kernel before 5.5.8, get_raw_socket in
    drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel
    stack corruption via crafted system
    calls.(CVE-2020-10942)

  - An issue was discovered in slc_bump in
    drivers/net/can/slcan.c in the Linux kernel through
    5.6.2. It allows attackers to read uninitialized
    can_frame data, potentially containing sensitive
    information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)

  - An issue was discovered in the Linux kernel through
    5.6.2. mpol_parse_str in mm/mempolicy.c has a
    stack-based out-of-bounds write because an empty
    nodelist is mishandled during mount option parsing, aka
    CID-aa9f7d5172fa. NOTE: Someone in the security
    community disagrees that this is a vulnerability
    because the issue 'is a bug in parsing mount options
    which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not
    already held.'.(CVE-2020-11565)

  - An issue was discovered in the Linux kernel before
    5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d.(CVE-2020-11608)

  - The kernel in Red Hat Enterprise Linux 7 and MRG-2 does
    not clear garbage data for SG_IO buffer, which may
    leaking sensitive information to
    userspace.(CVE-2014-8181)

  - In the Linux kernel 5.0.21, mounting a crafted ext4
    filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in
    ext4_put_super in fs/ext4/super.c, related to
    dump_orphan_list in fs/ext4/super.c.(CVE-2019-19447)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2150
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6bf6b88");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14331");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13974");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

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

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-514.44.5.10.h275",
        "kernel-debuginfo-3.10.0-514.44.5.10.h275",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h275",
        "kernel-devel-3.10.0-514.44.5.10.h275",
        "kernel-headers-3.10.0-514.44.5.10.h275",
        "kernel-tools-3.10.0-514.44.5.10.h275",
        "kernel-tools-libs-3.10.0-514.44.5.10.h275",
        "perf-3.10.0-514.44.5.10.h275",
        "python-perf-3.10.0-514.44.5.10.h275"];

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
