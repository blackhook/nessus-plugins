#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5755.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138418);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2019-3846",
    "CVE-2019-7308",
    "CVE-2019-15214",
    "CVE-2019-15220",
    "CVE-2019-19054",
    "CVE-2019-19533",
    "CVE-2019-19534",
    "CVE-2019-19536",
    "CVE-2020-0543",
    "CVE-2020-10690",
    "CVE-2020-10711",
    "CVE-2020-10757",
    "CVE-2020-12464",
    "CVE-2020-12652",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12655",
    "CVE-2020-12657",
    "CVE-2020-12770"
  );

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2020-5755)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-5755 advisory.

  - A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the
    mwifiex kernel module while connecting to a malicious wireless network. (CVE-2019-3846)

  - A NULL pointer dereference flaw was found in the Linux kernel's SELinux subsystem in versions before 5.7.
    This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into
    the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. While processing the CIPSO
    restricted bitmap tag in the 'cipso_v4_parsetag_rbm' routine, it sets the security attribute to indicate
    that the category bitmap is present, even if it has not been allocated. This issue leads to a NULL pointer
    dereference issue while importing the same category bitmap into SELinux. This flaw allows a remote network
    user to crash the system kernel, resulting in a denial of service. (CVE-2020-10711)

  - In the Linux kernel before 5.3.11, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/net/can/usb/peak_usb/pcan_usb_core.c driver, aka CID-f7a1337f0d29. (CVE-2019-19534)

  - An issue was found in Linux kernel before 5.5.4. mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka CID-3a9b153c5591. (CVE-2020-12654)

  - Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-0543)

  - usb_sg_cancel in drivers/usb/core/message.c in the Linux kernel before 5.6.8 has a use-after-free because
    a transfer occurs without a reference, aka CID-056ad39ee925. (CVE-2020-12464)

  - An issue was found in Linux kernel before 5.5.4. The mwifiex_cmd_append_vsie_tlv() function in
    drivers/net/wireless/marvell/mwifiex/scan.c allows local users to gain privileges or cause a denial of
    service because of an incorrect memcpy and buffer overflow, aka CID-b70261a288ea. (CVE-2020-12653)

  - An issue was discovered in the Linux kernel before 5.6.5. There is a use-after-free in block/bfq-iosched.c
    related to bfq_idle_slice_timer_body. (CVE-2020-12657)

  - An issue was discovered in the Linux kernel before 5.0.10. There is a use-after-free in the sound
    subsystem because card disconnection causes certain data structures to be deleted too early. This is
    related to sound/core/init.c and sound/core/info.c. (CVE-2019-15214)

  - In the Linux kernel before 5.3.4, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/media/usb/ttusb-dec/ttusb_dec.c driver, aka CID-a10feaf8c464. (CVE-2019-19533)

  - An issue was discovered in the Linux kernel before 5.2.1. There is a use-after-free caused by a malicious
    USB device in the drivers/net/wireless/intersil/p54/p54usb.c driver. (CVE-2019-15220)

  - A memory leak in the cx23888_ir_probe() function in drivers/media/pci/cx23885/cx23888-ir.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    kfifo_alloc() failures, aka CID-a7b2df76b42b. (CVE-2019-19054)

  - kernel/bpf/verifier.c in the Linux kernel before 4.20.6 performs undesirable out-of-bounds speculation on
    pointer arithmetic in various cases, including cases of different branches with different state or limits
    to sanitize, leading to side-channel attacks. (CVE-2019-7308)

  - There is a use-after-free in kernel versions before 5.5 due to a race condition between the release of
    ptp_clock and cdev while resource deallocation. When a (high privileged) process allocates a ptp device
    file (like /dev/ptpX) and voluntarily goes to sleep. During this time if the underlying device is removed,
    it can cause an exploitable condition as the process wakes up to terminate and clean all attached files.
    The system crashes due to the cdev structure being invalid (as already freed) which is pointed to by the
    inode. (CVE-2020-10690)

  - A flaw was found in the Linux Kernel in versions after 4.5-rc1 in the way mremap handled DAX Huge Pages.
    This flaw allows a local attacker with access to a DAX enabled storage to escalate their privileges on the
    system. (CVE-2020-10757)

  - The __mptctl_ioctl function in drivers/message/fusion/mptctl.c in the Linux kernel before 5.4.14 allows
    local users to hold an incorrect lock during the ioctl operation and trigger a race condition, i.e., a
    double fetch vulnerability, aka CID-28d76df18f0a. NOTE: the vendor states The security impact of this
    bug is not as bad as it could have been because these operations are all privileged and root already has
    enormous destructive power. (CVE-2020-12652)

  - An issue was discovered in xfs_agf_verify in fs/xfs/libxfs/xfs_alloc.c in the Linux kernel through 5.6.10.
    Attackers may trigger a sync of excessive duration via an XFS v5 image with crafted metadata, aka
    CID-d0c7feaf8767. (CVE-2020-12655)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - In the Linux kernel before 5.2.9, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/net/can/usb/peak_usb/pcan_usb_pro.c driver, aka CID-ead16e53c2f0. (CVE-2019-19536)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5755.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.14.35-1902.304.6.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2020-5755');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-4.14.35-1902.304.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-1902.304.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-1902.304.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-1902.304.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-doc-4.14.35-1902.304.6.el7uek', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-1902.304.6.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-4.14.35-1902.304.6.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
