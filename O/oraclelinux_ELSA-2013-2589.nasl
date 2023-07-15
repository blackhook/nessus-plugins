#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-2589.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71515);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id("CVE-2013-2141", "CVE-2013-4470", "CVE-2013-6367");
  script_bugtraq_id(60254, 63359, 64270);

  script_name(english:"Oracle Linux 5 / 6 : unbreakable enterprise kernel (ELSA-2013-2589)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2013-2589 advisory.

  - The do_tkill function in kernel/signal.c in the Linux kernel before 3.8.9 does not initialize a certain
    data structure, which allows local users to obtain sensitive information from kernel memory via a crafted
    application that makes a (1) tkill or (2) tgkill system call. (CVE-2013-2141)

  - The Linux kernel before 3.12, when UDP Fragmentation Offload (UFO) is enabled, does not properly
    initialize certain data structures, which allows local users to cause a denial of service (memory
    corruption and system crash) or possibly gain privileges via a crafted application that uses the UDP_CORK
    option in a setsockopt system call and sends both short and long packets, related to the
    ip_ufo_append_data function in net/ipv4/ip_output.c and the ip6_ufo_append_data function in
    net/ipv6/ip6_output.c. (CVE-2013-4470)

  - The apic_get_tmcct function in arch/x86/kvm/lapic.c in the KVM subsystem in the Linux kernel through
    3.12.5 allows guest OS users to cause a denial of service (divide-by-zero error and host OS crash) via
    crafted modifications of the TMICT value. (CVE-2013-6367)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-2589.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.4.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.4.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.33.4.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.4.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.4.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.33.4.el6uekdebug");
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
  var fixed_uptrack_levels = ['2.6.32-400.33.4.el5uek', '2.6.32-400.33.4.el6uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2013-2589');
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
    {'reference':'kernel-uek-2.6.32-400.33.4.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-2.6.32-400.33.4.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.4.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.4.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.4.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.4.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.4.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.4.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-400.33.4.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-400.33.4.el5uek', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.4.el5uek', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.4.el5uek', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'mlnx_en-2.6.32-400.33.4.el5uek-1.5.7-2', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.4.el5uek-1.5.7-2', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.4.el5uekdebug-1.5.7-2', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.4.el5uekdebug-1.5.7-2', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el5uek-1.5.1-4.0.58', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el5uek-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el5uekdebug-1.5.1-4.0.58', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el5uekdebug-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-uek-2.6.32-400.33.4.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-2.6.32-400.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.4.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-2.6.32-400.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.4.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-debug-devel-2.6.32-400.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.4.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-devel-2.6.32-400.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-2.6.32'},
    {'reference':'kernel-uek-doc-2.6.32-400.33.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-2.6.32'},
    {'reference':'kernel-uek-firmware-2.6.32-400.33.4.el6uek', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-firmware-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.4.el6uek', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'kernel-uek-headers-2.6.32-400.33.4.el6uek', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-2.6.32'},
    {'reference':'mlnx_en-2.6.32-400.33.4.el6uek-1.5.7-0.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.4.el6uek-1.5.7-0.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.4.el6uekdebug-1.5.7-0.1', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlnx_en-2.6.32-400.33.4.el6uekdebug-1.5.7-0.1', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el6uek-1.5.1-4.0.58', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el6uek-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el6uekdebug-1.5.1-4.0.58', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ofa-2.6.32-400.33.4.el6uekdebug-1.5.1-4.0.58', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
