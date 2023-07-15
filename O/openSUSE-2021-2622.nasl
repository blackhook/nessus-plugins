#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2622-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152255);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/06");

  script_cve_id("CVE-2020-2875", "CVE-2020-2933", "CVE-2020-2934");
  script_xref(name:"IAVA", value:"2020-A-0153");

  script_name(english:"openSUSE 15 Security Update : mysql-connector-java (openSUSE-SU-2021:2622-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2622-1 advisory.

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions
    that are affected are 8.0.14 and prior and 5.1.48 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors.
    Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in MySQL Connectors, attacks may significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of MySQL
    Connectors accessible data as well as unauthorized read access to a subset of MySQL Connectors accessible
    data. CVSS 3.0 Base Score 4.7 (Confidentiality and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N). (CVE-2020-2875)

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions
    that are affected are 5.1.48 and prior. Difficult to exploit vulnerability allows high privileged attacker
    with network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    MySQL Connectors. CVSS 3.0 Base Score 2.2 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-2933)

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions
    that are affected are 8.0.19 and prior and 5.1.48 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of MySQL Connectors
    accessible data as well as unauthorized read access to a subset of MySQL Connectors accessible data and
    unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Connectors. CVSS 3.0 Base
    Score 5.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L). (CVE-2020-2934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173600");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KHHGZ3MEHVZT3NYQIEG5WTISHLXRLW3D/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57cd638d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-2934");
  script_set_attribute(attribute:"solution", value:
"Update the affected mysql-connector-java package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-connector-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'mysql-connector-java-5.1.47-3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mysql-connector-java');
}
