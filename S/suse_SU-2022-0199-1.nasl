#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0199-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157145);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-4140",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22744",
    "CVE-2022-22745",
    "CVE-2022-22746",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0199-1");
  script_xref(name:"IAVA", value:"2022-A-0017-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaThunderbird (SUSE-SU-2022:0199-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:0199-1 advisory.

  - It was possible to construct specific XSLT markup that would be able to bypass an iframe sandbox. This
    vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2021-4140)

  - Constructing audio sinks could have lead to a race condition when playing audio files and closing windows.
    This could have lead to a use-after-free causing a potentially exploitable crash. This vulnerability
    affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22737)

  - Applying a CSS filter effect could have accessed out of bounds memory. This could have lead to a heap-
    buffer-overflow causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 91.5,
    Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22738)

  - Malicious websites could have tricked users into accepting launching a program to handle an external URL
    protocol. This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5.
    (CVE-2022-22739)

  - Certain network request objects were freed too early when releasing a network request handle. This could
    have lead to a use-after-free causing a potentially exploitable crash. This vulnerability affects Firefox
    ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22740)

  - When resizing a popup while requesting fullscreen access, the popup would have become unable to leave
    fullscreen mode. This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5.
    (CVE-2022-22741)

  - When inserting text while in edit mode, some characters might have lead to out-of-bounds memory access
    causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and
    Thunderbird < 91.5. (CVE-2022-22742)

  - When navigating from inside an iframe while requesting fullscreen access, an attacker-controlled tab could
    have made the browser unable to leave fullscreen mode. This vulnerability affects Firefox ESR < 91.5,
    Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22743)

  - The constructed curl command from the Copy as curl feature in DevTools was not properly escaped for
    PowerShell. This could have lead to command injection if pasted into a Powershell prompt.<br>*This bug
    only affects Thunderbird for Windows. Other operating systems are unaffected.*. This vulnerability affects
    Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22744)

  - Securitypolicyviolation events could have leaked cross-origin information for frame-ancestors violations.
    This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22745)

  - A race condition could have allowed bypassing the fullscreen notification which could have lead to a
    fullscreen window spoof being unnoticed.<br>*This bug only affects Firefox for Windows. Other operating
    systems are unaffected.*. This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird <
    91.5. (CVE-2022-22746)

  - After accepting an untrusted certificate, handling an empty pkcs7 sequence as part of the certificate data
    could have lead to a crash. This crash is believed to be unexploitable. This vulnerability affects Firefox
    ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22747)

  - Malicious websites could have confused Firefox into showing the wrong origin when asking to launch a
    program and handling an external URL protocol. This vulnerability affects Firefox ESR < 91.5, Firefox <
    96, and Thunderbird < 91.5. (CVE-2022-22748)

  - Mozilla developers Calixte Denizet, Kershaw Chang, Christian Holler, Jason Kratzer, Gabriele Svelto, Tyson
    Smith, Simon Giesecke, and Steve Fink reported memory safety bugs present in Firefox 95 and Firefox ESR
    91.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 91.5,
    Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22751)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194547");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-January/010081.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19ddc0c3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4140");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22751");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22751");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4140");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaThunderbird-91.5.0-8.51.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-91.5.0-8.51.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.5.0-8.51.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-91.5.0-8.51.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.5.0-8.51.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-91.5.0-8.51.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
