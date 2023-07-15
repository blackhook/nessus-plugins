#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10229-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(168393);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id(
    "CVE-2022-4174",
    "CVE-2022-4175",
    "CVE-2022-4176",
    "CVE-2022-4177",
    "CVE-2022-4178",
    "CVE-2022-4179",
    "CVE-2022-4180",
    "CVE-2022-4181",
    "CVE-2022-4182",
    "CVE-2022-4183",
    "CVE-2022-4184",
    "CVE-2022-4185",
    "CVE-2022-4186",
    "CVE-2022-4187",
    "CVE-2022-4188",
    "CVE-2022-4189",
    "CVE-2022-4190",
    "CVE-2022-4191",
    "CVE-2022-4192",
    "CVE-2022-4193",
    "CVE-2022-4194",
    "CVE-2022-4195"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2022:10229-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10229-1 advisory.

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4174)

  - Use after free in Camera Capture in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4175)

  - Out of bounds write in Lacros Graphics in Google Chrome on Chrome OS and Lacros prior to 108.0.5359.71
    allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially
    exploit heap corruption via UI interactions. (Chromium security severity: High) (CVE-2022-4176)

  - Use after free in Extensions in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a
    user to install an extension to potentially exploit heap corruption via a crafted Chrome Extension and UI
    interaction. (Chromium security severity: High) (CVE-2022-4177)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2022-4178)

  - Use after free in Audio in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4179)

  - Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (Chromium security severity: High) (CVE-2022-4180)

  - Use after free in Forms in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4181)

  - Inappropriate implementation in Fenced Frames in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass fenced frame restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4182)

  - Insufficient policy enforcement in Popup Blocker in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4183)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4184)

  - Inappropriate implementation in Navigation in Google Chrome on iOS prior to 108.0.5359.71 allowed a remote
    attacker to spoof the contents of the modal dialogue via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4185)

  - Insufficient validation of untrusted input in Downloads in Google Chrome prior to 108.0.5359.71 allowed an
    attacker who convinced a user to install a malicious extension to bypass Downloads restrictions via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2022-4186)

  - Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 108.0.5359.71 allowed a
    remote attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4187)

  - Insufficient validation of untrusted input in CORS in Google Chrome on Android prior to 108.0.5359.71
    allowed a remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2022-4188)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 108.0.5359.71 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2022-4189)

  - Insufficient data validation in Directory in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4190)

  - Use after free in Sign-In in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced
    a user to engage in specific UI interaction to potentially exploit heap corruption via profile
    destruction. (Chromium security severity: Medium) (CVE-2022-4191)

  - Use after free in Live Caption in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via UI
    interaction. (Chromium security severity: Medium) (CVE-2022-4192)

  - Insufficient policy enforcement in File System API in Google Chrome prior to 108.0.5359.71 allowed a
    remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2022-4193)

  - Use after free in Accessibility in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4194)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome prior to 108.0.5359.71 allowed a remote
    attacker to bypass Safe Browsing warnings via a malicious file. (Chromium security severity: Medium)
    (CVE-2022-4195)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205871");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IVDEECENZOGKBOMLYJ7KJTUJJSDCRO4I/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba794e15");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4186");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4190");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4195");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4194");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.3|SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3 / 15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-108.0.5359.71-bp154.2.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-108.0.5359.71-bp154.2.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-108.0.5359.71-bp154.2.49.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-108.0.5359.71-bp154.2.49.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-108.0.5359.71-bp154.2.49.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-108.0.5359.71-bp154.2.49.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-108.0.5359.71-bp154.2.49.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-108.0.5359.71-bp154.2.49.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
