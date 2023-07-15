#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0803-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158799);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2018-19787",
    "CVE-2020-27783",
    "CVE-2021-28957",
    "CVE-2021-43818"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0803-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : python-lxml (SUSE-SU-2022:0803-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:0803-1 advisory.

  - An issue was discovered in lxml before 4.2.5. lxml/html/clean.py in the lxml.html.clean module does not
    remove javascript: URLs that use escaping, allowing a remote attacker to conduct XSS attacks, as
    demonstrated by j a v a s c r i p t: in Internet Explorer. This is a similar issue to CVE-2014-3146.
    (CVE-2018-19787)

  - A XSS vulnerability was discovered in python-lxml's clean module. The module's parser didn't properly
    imitate browsers, which caused different behaviors between the sanitizer and the user's page. A remote
    attacker could exploit this flaw to run arbitrary HTML/JS code. (CVE-2020-27783)

  - An XSS vulnerability was discovered in python-lxml's clean module versions before 4.6.3. When disabling
    the safe_attrs_only and forms arguments, the Cleaner class does not remove the formaction attribute
    allowing for JS to bypass the sanitizer. A remote attacker could exploit this flaw to run arbitrary JS
    code on users who interact with incorrectly sanitized HTML. This issue is patched in lxml 4.6.3.
    (CVE-2021-28957)

  - lxml is a library for processing XML and HTML in the Python language. Prior to version 4.6.5, the HTML
    Cleaner in lxml.html lets certain crafted script content pass through, as well as script content in SVG
    files embedded using data URIs. Users that employ the HTML cleaner in a security relevant context should
    upgrade to lxml 4.6.5 to receive a patch. There are no known workarounds available. (CVE-2021-43818)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193752");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010414.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66eb70d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43818");
  script_set_attribute(attribute:"solution", value:
"Update the affected python2-lxml, python2-lxml-devel, python3-lxml and / or python3-lxml-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-lxml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-lxml-devel");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2', 'SLE_RT-release-15.2']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2', 'SLE_RT-release-15.2']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-python2-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-python2-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-python2-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-python2-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python2-lxml-4.7.1-3.7.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'python2-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'python3-lxml-4.7.1-3.7.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'python3-lxml-devel-4.7.1-3.7.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python2-lxml / python2-lxml-devel / python3-lxml / python3-lxml-devel');
}
