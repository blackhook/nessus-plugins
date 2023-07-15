#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137024);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2014-8181",
    "CVE-2018-9518",
    "CVE-2019-9444",
    "CVE-2019-14898",
    "CVE-2019-16230",
    "CVE-2019-19036",
    "CVE-2019-19377",
    "CVE-2019-20636",
    "CVE-2020-0066",
    "CVE-2020-10942",
    "CVE-2020-11494",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-12114",
    "CVE-2020-12464",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2020-1606)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In the Linux kernel 5.0.21, mounting a crafted btrfs
    filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in
    btrfs_queue_work in
    fs/btrfs/async-thread.c.(CVE-2019-19377)

  - The fix for CVE-2019-11599, affecting the Linux kernel
    before 5.0.10 was not complete. A local user could use
    this flaw to obtain sensitive information, cause a
    denial of service, or possibly have other unspecified
    impacts by triggering a race condition with
    mmget_not_zero or get_task_mm calls.(CVE-2019-14898)

  - A pivot_root race condition in fs/namespace.c in the
    Linux kernel 4.4.x before 4.4.221, 4.9.x before
    4.9.221, 4.14.x before 4.14.178, 4.19.x before
    4.19.119, and 5.x before 5.3 allows local users to
    cause a denial of service (panic) by corrupting a
    mountpoint reference counter.(CVE-2020-12114)

  - usb_sg_cancel in drivers/usb/core/message.c in the
    Linux kernel before 5.6.8 has a use-after-free because
    a transfer occurs without a reference, aka
    CID-056ad39ee925.(CVE-2020-12464)

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

  - In nfc_llcp_build_sdreq_tlv of llcp_commands.c, there
    is a possible out of bounds write due to a missing
    bounds check. This could lead to local escalation of
    privilege with System execution privileges needed. User
    interaction is not needed for exploitation. Product:
    Android. Versions: Android kernel. Android ID:
    A-73083945.(CVE-2018-9518)

  - An issue was discovered in slc_bump in
    drivers/net/can/slcan.c in the Linux kernel through
    5.6.2. It allows attackers to read uninitialized
    can_frame data, potentially containing sensitive
    information from kernel stack memory, if the
    configuration lacks CONFIG_INIT_STACK_ALL, aka
    CID-b9258a2cece4.(CVE-2020-11494)

  - In the Android kernel in sync debug fs driver there is
    a kernel pointer leak due to the usage of printf with
    %p. This could lead to local information disclosure
    with system execution privileges needed. User
    interaction is not needed for
    exploitation.(CVE-2019-9444)

  - In the Linux kernel before 5.4.12,
    drivers/input/input.c has out-of-bounds writes via a
    crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)

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

  - An issue was discovered in the stv06xx subsystem in the
    Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)

  - In the Linux kernel before 5.5.8, get_raw_socket in
    drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel
    stack corruption via crafted system
    calls.(CVE-2020-10942)

  - drivers/gpu/drm/radeon/radeon_display.c in the Linux
    kernel 5.2.14 does not check the alloc_workqueue return
    value, leading to a NULL pointer dereference. NOTE: A
    third-party software maintainer states that the work
    queue allocation is happening during device
    initialization, which for a graphics card occurs during
    boot. It is not attacker controllable and OOM at that
    time is highly unlikely.(CVE-2019-16230)

  - In the netlink driver, there is a possible out of
    bounds write due to a race condition. This could lead
    to local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-65025077(CVE-2020-0066)

  - The kernel in Red Hat Enterprise Linux 7 and MRG-2 does
    not clear garbage data for SG_IO buffer, which may
    leaking sensitive information to
    userspace.(CVE-2014-8181)

  - btrfs_root_node in fs/btrfs/ctree.c in the Linux kernel
    through 5.3.12 allows a NULL pointer dereference
    because rcu_dereference(root->node) can be
    zero.(CVE-2019-19036)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1606
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?027d6349");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12464");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.5.h442.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h442.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h442.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h442.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h442.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h442.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h442.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
