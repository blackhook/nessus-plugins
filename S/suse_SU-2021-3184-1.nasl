#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3184-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153577);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-3672",
    "CVE-2021-22930",
    "CVE-2021-22931",
    "CVE-2021-22939",
    "CVE-2021-22940"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3184-1");
  script_xref(name:"IAVB", value:"2021-B-0050-S");

  script_name(english:"SUSE SLES12 Security Update : nodejs14 (SUSE-SU-2021:3184-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3184-1 advisory.

  - nodejs: Use-after-free on close http2 on stream canceling (CVE-2021-22930)

  - Node.js before 16.6.0, 14.17.4, and 12.22.4 is vulnerable to Remote Code Execution, XSS, Application
    crashes due to missing input validation of host names returned by Domain Name Servers in Node.js dns
    library which can lead to output of wrong hostnames (leading to Domain Hijacking) and injection
    vulnerabilities in applications using the library. (CVE-2021-22931)

  - If the Node.js https API was used incorrectly and undefined was in passed for the rejectUnauthorized
    parameter, no error was returned and connections to servers with an expired certificate would have been
    accepted. (CVE-2021-22939)

  - Node.js before 16.6.1, 14.17.5, and 12.22.5 is vulnerable to a use after free attack where an attacker
    might be able to exploit the memory corruption, to change process behavior. (CVE-2021-22940)

  - c-ares: Missing input validation of host names may lead to domain hijacking (CVE-2021-3672)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189370");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-September/009484.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6a39ccc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3672");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs14, nodejs14-devel, nodejs14-docs and / or npm14 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22931");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'nodejs14-14.17.5-6.15.3', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-14.17.5-6.15.3', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-14.17.5-6.15.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-14.17.5-6.15.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-devel-14.17.5-6.15.3', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-devel-14.17.5-6.15.3', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-devel-14.17.5-6.15.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-devel-14.17.5-6.15.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-docs-14.17.5-6.15.3', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-docs-14.17.5-6.15.3', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-docs-14.17.5-6.15.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'nodejs14-docs-14.17.5-6.15.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'npm14-14.17.5-6.15.3', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'npm14-14.17.5-6.15.3', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'npm14-14.17.5-6.15.3', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'npm14-14.17.5-6.15.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs14 / nodejs14-devel / nodejs14-docs / npm14');
}
