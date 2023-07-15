#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-2585.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71134);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2012-6545",
    "CVE-2013-0343",
    "CVE-2013-1928",
    "CVE-2013-2164",
    "CVE-2013-2234",
    "CVE-2013-2888",
    "CVE-2013-2889",
    "CVE-2013-2892",
    "CVE-2013-3231",
    "CVE-2013-4345",
    "CVE-2013-4591"
  );
  script_bugtraq_id(
    58795,
    58906,
    58991,
    59390,
    60375,
    60874,
    62042,
    62043,
    62049,
    62740,
    63791
  );

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise Kernel (ELSA-2013-2585)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2013-2585 advisory.

  - The Bluetooth RFCOMM implementation in the Linux kernel before 3.6 does not properly initialize certain
    structures, which allows local users to obtain sensitive information from kernel memory via a crafted
    application. (CVE-2012-6545)

  - The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel before 3.9-rc7 does not initialize a
    certain length variable, which allows local users to obtain sensitive information from kernel stack memory
    via a crafted recvmsg or recvfrom system call. (CVE-2013-3231)

  - The mmc_ioctl_cdrom_read_data function in drivers/cdrom/cdrom.c in the Linux kernel through 3.10 allows
    local users to obtain sensitive information from kernel memory via a read operation on a malfunctioning
    CD-ROM drive. (CVE-2013-2164)

  - The (1) key_notify_sa_flush and (2) key_notify_policy_flush functions in net/key/af_key.c in the Linux
    kernel before 3.10 do not initialize certain structure members, which allows local users to obtain
    sensitive information from kernel heap memory by reading a broadcast message from the notify interface of
    an IPSec key_socket. (CVE-2013-2234)

  - The ipv6_create_tempaddr function in net/ipv6/addrconf.c in the Linux kernel through 3.8 does not properly
    handle problems with the generation of IPv6 temporary addresses, which allows remote attackers to cause a
    denial of service (excessive retries and address-generation outage), and consequently obtain sensitive
    information, via ICMPv6 Router Advertisement (RA) messages. (CVE-2013-0343)

  - Off-by-one error in the get_prng_bytes function in crypto/ansi_cprng.c in the Linux kernel through 3.11.4
    makes it easier for context-dependent attackers to defeat cryptographic protection mechanisms via multiple
    requests for small amounts of data, leading to improper management of the state of the consumed data.
    (CVE-2013-4345)

  - The do_video_set_spu_palette function in fs/compat_ioctl.c in the Linux kernel before 3.6.5 on unspecified
    architectures lacks a certain error check, which might allow local users to obtain sensitive information
    from kernel stack memory via a crafted VIDEO_SET_SPU_PALETTE ioctl call on a /dev/dvb device.
    (CVE-2013-1928)

  - Multiple array index errors in drivers/hid/hid-core.c in the Human Interface Device (HID) subsystem in the
    Linux kernel through 3.11 allow physically proximate attackers to execute arbitrary code or cause a denial
    of service (heap memory corruption) via a crafted device that provides an invalid Report ID.
    (CVE-2013-2888)

  - drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11,
    when CONFIG_HID_ZEROPLUS is enabled, allows physically proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted device. (CVE-2013-2889)

  - drivers/hid/hid-pl.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_PANTHERLORD is enabled, allows physically proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted device. (CVE-2013-2892)

  - Buffer overflow in the __nfs4_get_acl_uncached function in fs/nfs/nfs4proc.c in the Linux kernel before
    3.7.2 allows local users to cause a denial of service (memory corruption and system crash) or possibly
    have unspecified other impact via a getxattr system call for the system.nfs4_acl extended attribute of a
    pathname on an NFSv4 filesystem. (CVE-2013-4591)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-2585.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4591");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.3.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.3.el6uekdebug");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-400.33.3.el5uek', '2.6.32-400.33.3.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2013-2585');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-2.6.32-400.33.3.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-2.6.32-400.33.3.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.3.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.3.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.3.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.3.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.3.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.3.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-400.33.3.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-400.33.3.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.3.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.3.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'mlnx_en-2.6.32-400.33.3.el5uek-1.5.7-2', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.3.el5uek-1.5.7-2', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.3.el5uekdebug-1.5.7-2', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.3.el5uekdebug-1.5.7-2', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el5uek-1.5.1-4.0.58', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el5uek-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el5uekdebug-1.5.1-4.0.58', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el5uekdebug-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-2.6.32-400.33.3.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-2.6.32-400.33.3.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.3.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.3.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.3.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.3.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.3.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.3.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-400.33.3.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-400.33.3.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.3.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.3.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'mlnx_en-2.6.32-400.33.3.el6uek-1.5.7-0.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.3.el6uek-1.5.7-0.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.3.el6uekdebug-1.5.7-0.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.3.el6uekdebug-1.5.7-0.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el6uek-1.5.1-4.0.58', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el6uek-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el6uekdebug-1.5.1-4.0.58', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.3.el6uekdebug-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
