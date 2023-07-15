#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-015e4d696d
#

include('compat.inc');

if (description)
{
  script_id(172671);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2023-0927",
    "CVE-2023-0928",
    "CVE-2023-0929",
    "CVE-2023-0930",
    "CVE-2023-0931",
    "CVE-2023-0932",
    "CVE-2023-0933",
    "CVE-2023-0941",
    "CVE-2023-1213",
    "CVE-2023-1214",
    "CVE-2023-1215",
    "CVE-2023-1216",
    "CVE-2023-1217",
    "CVE-2023-1218",
    "CVE-2023-1219",
    "CVE-2023-1220",
    "CVE-2023-1221",
    "CVE-2023-1222",
    "CVE-2023-1223",
    "CVE-2023-1224",
    "CVE-2023-1225",
    "CVE-2023-1226",
    "CVE-2023-1227"
  );
  script_xref(name:"FEDORA", value:"2023-015e4d696d");

  script_name(english:"Fedora 36 : chromium (2023-015e4d696d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-015e4d696d advisory.

  - Use after free in Web Payments API in Google Chrome on Android prior to 110.0.5481.177 allowed a remote
    attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2023-0927)

  - Use after free in SwiftShader in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-0928)

  - Use after free in Vulkan in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0929)

  - Heap buffer overflow in Video in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-0930)

  - Use after free in Video in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0931)

  - Use after free in WebRTC in Google Chrome on Windows prior to 110.0.5481.177 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2023-0932)

  - Integer overflow in PDF in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: Medium) (CVE-2023-0933)

  - Use after free in Prompts in Google Chrome prior to 110.0.5481.177 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-0941)

  - Use after free in Swiftshader in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1213)

  - Type confusion in V8 in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1214)

  - Type confusion in CSS in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1215)

  - Use after free in DevTools in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    convienced the user to engage in direct UI interaction to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2023-1216)

  - Stack buffer overflow in Crash reporting in Google Chrome on Windows prior to 111.0.5563.64 allowed a
    remote attacker who had compromised the renderer process to obtain potentially sensitive information from
    process memory via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1217)

  - Use after free in WebRTC in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1218)

  - Heap buffer overflow in Metrics in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1219)

  - Heap buffer overflow in UMA in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1220)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 111.0.5563.64 allowed an
    attacker who convinced a user to install a malicious extension to bypass navigation restrictions via a
    crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-1221)

  - Heap buffer overflow in Web Audio API in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1222)

  - Insufficient policy enforcement in Autofill in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1223)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1224)

  - Insufficient policy enforcement in Navigation in Google Chrome on iOS prior to 111.0.5563.64 allowed a
    remote attacker to bypass same origin policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1225)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass content security policy via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1226)

  - Use after free in Core in Google Chrome on Lacros prior to 111.0.5563.64 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via crafted
    UI interaction. (Chromium security severity: Medium) (CVE-2023-1227)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-015e4d696d");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0941");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'chromium-111.0.5563.64-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium');
}
