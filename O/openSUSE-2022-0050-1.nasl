#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0050-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156649);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2018-18065", "CVE-2020-15862");

  script_name(english:"openSUSE 15 Security Update : net-snmp (openSUSE-SU-2022:0050-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0050-1 advisory.

  - _set_key in agent/helpers/table_container.c in Net-SNMP before 5.8 has a NULL Pointer Exception bug that
    can be used by an authenticated attacker to remotely cause the instance to crash via a crafted UDP packet,
    resulting in Denial of Service. (CVE-2018-18065)

  - Net-SNMP through 5.7.3 has Improper Privilege Management because SNMP WRITE access to the EXTEND MIB
    provides the ability to run arbitrary commands as root. (CVE-2020-15862)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1027353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1081164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1108471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1111122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1116807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1145864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181591");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2OQK3YBZP7LLGFOZF2RYGZC5GDDRHRI6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b291299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-18065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15862");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsnmp30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:net-snmp-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libsnmp30-32bit-5.7.3-10.9.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsnmp30-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'net-snmp-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'net-snmp-devel-32bit-5.7.3-10.9.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'net-snmp-devel-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-SNMP-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python2-net-snmp-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-net-snmp-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'snmp-mibs-5.7.3-10.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsnmp30 / libsnmp30-32bit / net-snmp / net-snmp-devel / etc');
}
