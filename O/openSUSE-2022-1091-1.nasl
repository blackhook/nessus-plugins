#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:1091-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159477);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2021-3572", "CVE-2021-4189", "CVE-2022-0391");

  script_name(english:"openSUSE 15 Security Update : python (openSUSE-SU-2022:1091-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:1091-1 advisory.

  - A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote
    attacker could possibly use this issue to install a different revision on a repository. The highest threat
    from this vulnerability is to data integrity. This is fixed in python-pip version 21.1. (CVE-2021-3572)

  - Automatic update for python2.7-2.7.18-20.fc37.  ##### **Changelog**  ``` * Wed Feb 16 2022 Charalampos
    Stratakis <cstratak@redhat.com> - 2.7.18-20 - Security fixes for CVE-2021-4189 and CVE-2022-0391 Resolves:
    rhbz#2047376  ``` (CVE-2021-4189)

  - A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform
    Resource Locator (URL) strings into components. The issue involves how the urlparse method does not
    sanitize input and allows characters like '\r' and '\n' in the URL path. This flaw allows an attacker to
    input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1,
    3.9.5, 3.8.11, 3.7.11 and 3.6.14. (CVE-2022-0391)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195396");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ULIK4RFHGHTVVWROQ6NTBBB4JWOGWYD6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a8dfaa2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0391");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


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
    {'reference':'libpython2_7-1_0-2.7.18-150000.38.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libpython2_7-1_0-32bit-2.7.18-150000.38.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-2.7.18-150000.38.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-32bit-2.7.18-150000.38.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-base-2.7.18-150000.38.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-base-32bit-2.7.18-150000.38.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-curses-2.7.18-150000.38.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-demo-2.7.18-150000.38.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-devel-2.7.18-150000.38.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-gdbm-2.7.18-150000.38.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-idle-2.7.18-150000.38.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-tk-2.7.18-150000.38.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-xml-2.7.18-150000.38.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpython2_7-1_0 / libpython2_7-1_0-32bit / python / python-32bit / etc');
}
