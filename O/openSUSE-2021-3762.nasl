#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3762-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155665);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2021-23214", "CVE-2021-23222");
  script_xref(name:"IAVB", value:"2021-B-0067-S");

  script_name(english:"openSUSE 15 Security Update : postgresql13 (openSUSE-SU-2021:3762-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3762-1 advisory.

  - Server processes unencrypted bytes from man-in-the-middlemore details (CVE-2021-23214)

  - libpq processes unencrypted bytes from man-in-the-middlemore details (CVE-2021-23222)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192516");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TKUQ4NBJFXX6V3DRII3AKLC2VO5WMZJB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9906ced0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23222");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-llvmjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql13-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'postgresql13-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-contrib-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-devel-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-llvmjit-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-plperl-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-plpython-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-pltcl-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-server-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-server-devel-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql13-test-13.5-5.22.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'postgresql13 / postgresql13-contrib / postgresql13-devel / etc');
}
