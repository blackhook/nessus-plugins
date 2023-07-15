#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-2014.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68415);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2010-4346",
    "CVE-2010-4648",
    "CVE-2010-4655",
    "CVE-2010-4656",
    "CVE-2011-0521",
    "CVE-2011-0695",
    "CVE-2011-1010",
    "CVE-2011-1090",
    "CVE-2011-1478"
  );
  script_xref(name:"IAVA", value:"2011-A-0147-S");
  script_xref(name:"IAVA", value:"2012-A-0020-S");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2011-2014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2011-2014 advisory.

  - The install_special_mapping function in mm/mmap.c in the Linux kernel before 2.6.37-rc6 does not make an
    expected security_file_mmap function call, which allows local users to bypass intended mmap_min_addr
    restrictions and possibly conduct NULL pointer dereference attacks via a crafted assembly-language
    application. (CVE-2010-4346)

  - The orinoco_ioctl_set_auth function in drivers/net/wireless/orinoco/wext.c in the Linux kernel before
    2.6.37 does not properly implement a TKIP protection mechanism, which makes it easier for remote attackers
    to obtain access to a Wi-Fi network by reading Wi-Fi frames. (CVE-2010-4648)

  - net/core/ethtool.c in the Linux kernel before 2.6.36 does not initialize certain data structures, which
    allows local users to obtain potentially sensitive information from kernel heap memory by leveraging the
    CAP_NET_ADMIN capability for an ethtool ioctl call. (CVE-2010-4655)

  - The iowarrior_write function in drivers/usb/misc/iowarrior.c in the Linux kernel before 2.6.37 does not
    properly allocate memory, which might allow local users to trigger a heap-based buffer overflow, and
    consequently cause a denial of service or gain privileges, via a long report. (CVE-2010-4656)

  - The dvb_ca_ioctl function in drivers/media/dvb/ttpci/av7110_ca.c in the Linux kernel before 2.6.38-rc2
    does not check the sign of a certain integer field, which allows local users to cause a denial of service
    (memory corruption) or possibly have unspecified other impact via a negative value. (CVE-2011-0521)

  - Race condition in the cm_work_handler function in the InfiniBand driver (drivers/infiniband/core/cma.c) in
    Linux kernel 2.6.x allows remote attackers to cause a denial of service (panic) by sending an InfiniBand
    request while other request handlers are still running, which triggers an invalid pointer dereference.
    (CVE-2011-0695)

  - Buffer overflow in the mac_partition function in fs/partitions/mac.c in the Linux kernel before 2.6.37.2
    allows local users to cause a denial of service (panic) or possibly have unspecified other impact via a
    malformed Mac OS partition table. (CVE-2011-1010)

  - The __nfs4_proc_set_acl function in fs/nfs/nfs4proc.c in the Linux kernel before 2.6.38 stores NFSv4 ACL
    data in memory that is allocated by kmalloc but not properly freed, which allows local users to cause a
    denial of service (panic) via a crafted attempt to set an ACL. (CVE-2011-1090)

  - The napi_reuse_skb function in net/core/dev.c in the Generic Receive Offload (GRO) implementation in the
    Linux kernel before 2.6.38 does not reset the values of certain structure members, which might allow
    remote attackers to cause a denial of service (NULL pointer dereference) via a malformed VLAN frame.
    (CVE-2011-1478)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-2014.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.28.11.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.28.11.el5debug");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-100.28.11.el5', '2.6.32-100.28.11.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-2014');
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
    {'reference':'kernel-uek-2.6.32-100.28.11.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-100.28.11.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-100.28.11.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-100.28.11.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-100.28.11.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-100.28.11.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-100.28.11.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'ofa-2.6.32-100.28.11.el5-1.5.1-4.0.28', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-100.28.11.el5debug-1.5.1-4.0.28', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-2.6.32-100.28.11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-100.28.11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-100.28.11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-100.28.11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-100.28.11.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-100.28.11.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-100.28.11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'}
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
