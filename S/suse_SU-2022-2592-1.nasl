##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2592-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(163644);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-31163");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2592-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : rubygem-tzinfo (SUSE-SU-2022:2592-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by a vulnerability as
referenced in the SUSE-SU-2022:2592-1 advisory.

  - TZInfo is a Ruby library that provides access to time zone data and allows times to be converted using
    time zone rules. Versions prior to 0.36.1, as well as those prior to 1.2.10 when used with the Ruby data
    source tzinfo-data, are vulnerable to relative path traversal. With the Ruby data source, time zones are
    defined in Ruby files. There is one file per time zone. Time zone files are loaded with `require` on
    demand. In the affected versions, `TZInfo::Timezone.get` fails to validate time zone identifiers
    correctly, allowing a new line character within the identifier. With Ruby version 1.9.3 and later,
    `TZInfo::Timezone.get` can be made to load unintended files with `require`, executing them within the Ruby
    process. Versions 0.3.61 and 1.2.10 include fixes to correctly validate time zone identifiers. Versions
    2.0.0 and later are not vulnerable. Version 0.3.61 can still load arbitrary files from the Ruby load path
    if their name follows the rules for a valid time zone identifier and the file has a prefix of
    `tzinfo/definition` within a directory in the load path. Applications should ensure that untrusted files
    are not placed in a directory on the load path. As a workaround, the time zone identifier can be validated
    before passing to `TZInfo::Timezone.get` by ensuring it matches the regular expression
    `\A[A-Za-z0-9+\-_]+(?:\/[A-Za-z0-9+\-_]+)*\z`. (CVE-2022-31163)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201835");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-July/011712.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4049ab13");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31163");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby2.5-rubygem-tzinfo, ruby2.5-rubygem-tzinfo-doc and / or ruby2.5-rubygem-tzinfo-testsuite
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31163");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-tzinfo-doc-1.2.4-150000.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-tzinfo-testsuite-1.2.4-150000.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-tzinfo-doc-1.2.4-150000.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-tzinfo-testsuite-1.2.4-150000.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15']},
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.1']},
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ruby2.5-rubygem-tzinfo-1.2.4-150000.3.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby2.5-rubygem-tzinfo / ruby2.5-rubygem-tzinfo-doc / etc');
}
