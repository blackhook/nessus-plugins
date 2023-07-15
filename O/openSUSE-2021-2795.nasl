#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2795-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152727);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-21704");

  script_name(english:"openSUSE 15 Security Update : php7 (openSUSE-SU-2021:2795-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by a vulnerability as referenced in the
openSUSE-SU-2021:2795-1 advisory.

  - Tenable.sc leverages third-party software to help provide underlying functionality. Multiple third-party
    components were found to contain vulnerabilities, and updated versions have been made available by the
    providers.  Out of caution, and in line with best practice, Tenable has upgraded the bundled components to
    address the potential impact of these issues. Tenable.sc 5.19.0 updates the following components:   1.
    Handlebars CVE-2019-19919 Severity: Critical   2. Underscore CVE-2021-23358 Severity: High   3. Apache FOP
    CVE-2017-5661 Severity: High   4. Bootstrap CVE-2019-8331, CVE-2018-20676, CVE-2018-20677, CVE-2018-14040,
    CVE-2018-14042, CVE-2016-10735  Highest Severity: Medium   5. PHP CVE-2019-11041, CVE-2019-11042,
    CVE-2019-11043, CVE-2019-11044, CVE-2019-11045, CVE-2019-11046, CVE-2019-11047, CVE-2019-11048,
    CVE-2019-11049, CVE-2019-11050, CVE-2020-7059, CVE-2020-7060, CVE-2020-7061, CVE-2020-7062, CVE-2020-7063,
    CVE-2020-7064, CVE-2020-7065, CVE-2020-7066, CVE-2020-7067, CVE-2020-7068, CVE-2020-7069, CVE-2020-7070,
    CVE-2020-7071, CVE-2021-21702, CVE-2021-21704, CVE-2021-21705 Highest Severity: Critical   6. sqlite
    CVE-2019-16168, CVE-2019-19645, CVE-2019-19646, CVE-2020-11655, CVE-2020-11656, CVE-2020-13434,
    CVE-2020-13435, CVE-2020-13630, CVE-2020-13631, CVE-2020-13632, CVE-2020-15358  Highest Severity: Critical
    7. SimpleSAMLPHP CVE-2020-11022 Severity: Medium  Tenable has released Tenable.sc 5.19.0 to address these
    issues. The installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/tenable-sc). (CVE-2021-21704)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188035");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7OI533FKAZPJKSHOKRDDHYZBMHCKP25U/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b78aac22");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21704");
  script_set_attribute(attribute:"solution", value:
"Update the affected php7-wddx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-wddx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'php7-wddx-7.2.5-4.79.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php7-wddx');
}
