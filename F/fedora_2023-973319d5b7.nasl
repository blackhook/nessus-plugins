#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-973319d5b7
#

include('compat.inc');

if (description)
{
  script_id(173881);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id(
    "CVE-2023-23918",
    "CVE-2023-23919",
    "CVE-2023-23920",
    "CVE-2023-23936",
    "CVE-2023-24807"
  );
  script_xref(name:"FEDORA", value:"2023-973319d5b7");

  script_name(english:"Fedora 38 : nodejs16 / nodejs18 / nodejs20 (2023-973319d5b7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-973319d5b7 advisory.

  - A privilege escalation vulnerability exists in Node.js <19.6.1, <18.14.1, <16.19.1 and <14.21.3 that made
    it possible to bypass the experimental Permissions (https://nodejs.org/api/permissions.html) feature in
    Node.js and access non authorized modules by using process.mainModule.require(). This only affects users
    who had enabled the experimental permissions option with --experimental-policy. (CVE-2023-23918)

  - A cryptographic vulnerability exists in Node.js <19.2.0, <18.14.1, <16.19.1, <14.21.3 that in some cases
    did does not clear the OpenSSL error stack after operations that may set it. This may lead to false
    positive errors during subsequent cryptographic operations that happen to be on the same thread. This in
    turn could be used to cause a denial of service. (CVE-2023-23919)

  - An untrusted search path vulnerability exists in Node.js. <19.6.1, <18.14.1, <16.19.1, and <14.21.3 that
    could allow an attacker to search and potentially load ICU data when running with elevated privileges.
    (CVE-2023-23920)

  - Undici is an HTTP/1.1 client for Node.js. Starting with version 2.0.0 and prior to version 5.19.1, the
    undici library does not protect `host` HTTP header from CRLF injection vulnerabilities. This issue is
    patched in Undici v5.19.1. As a workaround, sanitize the `headers.host` string before passing to undici.
    (CVE-2023-23936)

  - Undici is an HTTP/1.1 client for Node.js. Prior to version 5.19.1, the `Headers.set()` and
    `Headers.append()` methods are vulnerable to Regular Expression Denial of Service (ReDoS) attacks when
    untrusted values are passed into the functions. This is due to the inefficient regular expression used to
    normalize the values in the `headerValueNormalize()` utility function. This vulnerability was patched in
    v5.19.1. No known workarounds are available. (CVE-2023-24807)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-973319d5b7");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:nodejs16, 1:nodejs18 and / or 1:nodejs20 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs20");
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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nodejs16-16.20.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs18-18.15.0-6.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs20-19.8.1-7.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs16 / nodejs18 / nodejs20');
}
