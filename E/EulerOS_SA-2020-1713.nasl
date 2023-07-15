#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137932);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2014-8181",
    "CVE-2017-5967",
    "CVE-2019-18675",
    "CVE-2019-19768",
    "CVE-2019-20636",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-8992",
    "CVE-2020-9383",
    "CVE-2020-10741",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-11608",
    "CVE-2020-11609",
    "CVE-2020-11668",
    "CVE-2020-12464",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-13143"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : kernel (EulerOS-SA-2020-1713)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - In the Linux kernel 5.4.0-rc2, there is a
    use-after-free (read) in the __blk_add_trace function
    in kernel/trace/blktrace.c (which is used to fill out a
    blk_io_trace structure and place it in a per-cpu
    sub-buffer).(CVE-2019-19768)

  - The Linux kernel through 5.3.13 has a start_offset+size
    Integer Overflow in cpia2_remap_buffer in
    drivers/media/usb/cpia2/cpia2_core.c because cpia2 has
    its own mmap implementation. This allows local users
    (with /dev/video0 access) to obtain read and write
    permissions on kernel physical pages, which can
    possibly result in a privilege
    escalation.(CVE-2019-18675)

  - An issue was discovered in the Linux kernel through
    5.5.6. set_fdc in drivers/block/floppy.c leads to a
    wait_til_ready out-of-bounds read because the FDC index
    is not checked for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vgacon_invert_region
    function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)

  - The time subsystem in the Linux kernel, when
    CONFIG_TIMER_STATS is enabled, allows local users to
    discover real PID values (as distinguished from PID
    values inside a PID namespace) by reading the
    /proc/timer_list file, related to the print_timer
    function in kernel/time/timer_list.c and the
    __timer_stats_timer_set_start_info function in
    kernel/time/timer.c.(CVE-2017-5967)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2014-8181)

  - ext4_protect_reserved_inode in fs/ext4/block_validity.c
    in the Linux kernel through 5.5.3 allows attackers to
    cause a denial of service (soft lockup) via a crafted
    journal size.(CVE-2020-8992)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.
    ConsultIDs: CVE-2020-12826. Reason: This candidate is a
    duplicate of CVE-2020-12826. Notes: All CVE users
    should reference CVE-2020-12826 instead of this
    candidate. All references and descriptions in this
    candidate have been removed to prevent accidental
    usage.(CVE-2020-10741)

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

  - gadget_dev_desc_UDC_store in
    drivers/usb/gadget/configfs.c in the Linux kernel
    through 5.6.13 relies on kstrdup without considering
    the possibility of an internal '\0' value, which allows
    attackers to trigger an out-of-bounds read, aka
    CID-15753588bcd4.(CVE-2020-13143)

  - An issue was discovered in the Linux kernel through
    5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka
    CID-83c6f2390040.(CVE-2020-12770)

  - An issue was found in Linux kernel before 5.5.4.
    mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a
    remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka
    CID-3a9b153c5591.(CVE-2020-12654)

  - An issue was found in Linux kernel before 5.5.4. The
    mwifiex_cmd_append_vsie_tlv() function in
    drivers/net/wireless/marvell/mwifiex/scan.c allows
    local users to gain privileges or cause a denial of
    service because of an incorrect memcpy and buffer
    overflow, aka CID-b70261a288ea.(CVE-2020-12653)

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

  - In the Linux kernel before 5.6.1,
    drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink
    camera USB driver) mishandles invalid descriptors, aka
    CID-a246b4d54770.(CVE-2020-11668)

  - An issue was discovered in the stv06xx subsystem in the
    Linux kernel before 5.6.1.
    drivers/media/usb/gspca/stv06xx/stv06xx.c and
    drivers/media/usb/gspca/stv06xx/stv06xx_pb0100.c
    mishandle invalid descriptors, as demonstrated by a
    NULL pointer dereference, aka
    CID-485b06aadb93.(CVE-2020-11609)

  - An issue was discovered in the Linux kernel before
    5.6.1. drivers/media/usb/gspca/ov519.c allows NULL
    pointer dereferences in ov511_mode_init_regs and
    ov518_mode_init_regs when there are zero endpoints, aka
    CID-998912346c0d.(CVE-2020-11608)

  - ** DISPUTED ** An issue was discovered in the Linux
    kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c
    has a stack-based out-of-bounds write because an empty
    nodelist is mishandled during mount option parsing, aka
    CID-aa9f7d5172fa. NOTE: Someone in the security
    community disagrees that this is a vulnerability
    because the issue 'is a bug in parsing mount options
    which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not
    already held.'.(CVE-2020-11565)

  - In the Linux kernel before 5.4.12,
    drivers/input/input.c has out-of-bounds writes via a
    crafted keycode table, as demonstrated by
    input_set_keycode, aka
    CID-cb222aed03d7.(CVE-2019-20636)

  - In the Linux kernel before 5.5.8, get_raw_socket in
    drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel
    stack corruption via crafted system
    calls.(CVE-2020-10942)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1713
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4dbca16");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12464");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_111",
        "kernel-devel-3.10.0-862.14.1.6_111",
        "kernel-headers-3.10.0-862.14.1.6_111",
        "kernel-tools-3.10.0-862.14.1.6_111",
        "kernel-tools-libs-3.10.0-862.14.1.6_111",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_111",
        "perf-3.10.0-862.14.1.6_111",
        "python-perf-3.10.0-862.14.1.6_111"];

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
