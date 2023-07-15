#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1144-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152515);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-30565",
    "CVE-2021-30566",
    "CVE-2021-30567",
    "CVE-2021-30568",
    "CVE-2021-30569",
    "CVE-2021-30571",
    "CVE-2021-30572",
    "CVE-2021-30573",
    "CVE-2021-30574",
    "CVE-2021-30575",
    "CVE-2021-30576",
    "CVE-2021-30577",
    "CVE-2021-30578",
    "CVE-2021-30579",
    "CVE-2021-30581",
    "CVE-2021-30582",
    "CVE-2021-30584",
    "CVE-2021-30585",
    "CVE-2021-30588",
    "CVE-2021-30589",
    "CVE-2021-30590",
    "CVE-2021-30591",
    "CVE-2021-30592",
    "CVE-2021-30593",
    "CVE-2021-30594",
    "CVE-2021-30596",
    "CVE-2021-30597"
  );
  script_xref(name:"IAVA", value:"2021-A-0346-S");
  script_xref(name:"IAVA", value:"2021-A-0361-S");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2021:1144-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1144-1 advisory.

  - Out of bounds write in Tab Groups in Google Chrome on Linux and ChromeOS prior to 92.0.4515.107 allowed an
    attacker who convinced a user to install a malicious extension to perform an out of bounds memory write
    via a crafted HTML page. (CVE-2021-30565)

  - Stack buffer overflow in Printing in Google Chrome prior to 92.0.4515.107 allowed a remote attacker who
    had compromised the renderer process to potentially exploit stack corruption via a crafted HTML page.
    (CVE-2021-30566)

  - Use after free in DevTools in Google Chrome prior to 92.0.4515.107 allowed an attacker who convinced a
    user to open DevTools to potentially exploit heap corruption via specific user gesture. (CVE-2021-30567)

  - Heap buffer overflow in WebGL in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30568)

  - Use after free in sqlite in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30569)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 92.0.4515.107 allowed an attacker
    who convinced a user to install a malicious extension to potentially perform a sandbox escape via a
    crafted HTML page. (CVE-2021-30571)

  - Use after free in Autofill in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30572)

  - Use after free in GPU in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30573)

  - Use after free in protocol handling in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30574)

  - Out of bounds write in Autofill in Google Chrome prior to 92.0.4515.107 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30575)

  - Use after free in DevTools in Google Chrome prior to 92.0.4515.107 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30576, CVE-2021-30581)

  - Insufficient policy enforcement in Installer in Google Chrome prior to 92.0.4515.107 allowed a remote
    attacker to perform local privilege escalation via a crafted file. (CVE-2021-30577)

  - Uninitialized use in Media in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to perform
    out of bounds memory access via a crafted HTML page. (CVE-2021-30578)

  - Use after free in UI framework in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30579)

  - Inappropriate implementation in Animation in Google Chrome prior to 92.0.4515.107 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-30582)

  - Incorrect security UI in Downloads in Google Chrome on Android prior to 92.0.4515.107 allowed a remote
    attacker to perform domain spoofing via a crafted HTML page. (CVE-2021-30584)

  - Use after free in sensor handling in Google Chrome on Windows prior to 92.0.4515.107 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30585)

  - Type confusion in V8 in Google Chrome prior to 92.0.4515.107 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30588)

  - Insufficient validation of untrusted input in Sharing in Google Chrome prior to 92.0.4515.107 allowed a
    remote attacker to bypass navigation restrictions via a crafted click-to-call link. (CVE-2021-30589)

  - Heap buffer overflow in Bookmarks. (CVE-2021-30590)

  - Use after free in File System API. (CVE-2021-30591)

  - Out of bounds write in Tab Groups. (CVE-2021-30592)

  - Out of bounds read in Tab Strip. (CVE-2021-30593)

  - Use after free in Page Info UI. (CVE-2021-30594)

  - This CVE was assigned by Chrome. Microsoft Edge (Chromium-based) ingests Chromium, which addresses this
    vulnerability. Please see Google Chrome Releases for more information. (CVE-2021-30596)

  - Use after free in Browser UI. (CVE-2021-30597)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189006");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JXI3OZYD3ADIBS3KBG3HYP2WXAJHKIDA/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbc8be44");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30573");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30597");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30592");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
    {'reference':'chromedriver-92.0.4515.131-bp153.2.19.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-92.0.4515.131-bp153.2.19.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-92.0.4515.131-bp153.2.19.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-92.0.4515.131-bp153.2.19.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
