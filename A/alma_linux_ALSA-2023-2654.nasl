#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:2654.
##

include('compat.inc');

if (description)
{
  script_id(175571);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id(
    "CVE-2021-35065",
    "CVE-2022-4904",
    "CVE-2022-25881",
    "CVE-2023-23918",
    "CVE-2023-23919",
    "CVE-2023-23920",
    "CVE-2023-23936",
    "CVE-2023-24807"
  );
  script_xref(name:"ALSA", value:"2023:2654");

  script_name(english:"AlmaLinux 9 : nodejs:18 (ALSA-2023:2654)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:2654 advisory.

  - The glob-parent package before 6.0.1 for Node.js allows ReDoS (regular expression denial of service)
    attacks against the enclosure regular expression. (CVE-2021-35065)

  - This affects versions of the package http-cache-semantics before 4.1.1. The issue can be exploited via
    malicious request header values sent to a server, when that server reads the cache policy from the request
    using this library. (CVE-2022-25881)

  - A flaw was found in the c-ares package. The ares_set_sortlist is missing checks about the validity of the
    input string, which allows a possible arbitrary length stack overflow. This issue may cause a denial of
    service or a limited impact on confidentiality and integrity. (CVE-2022-4904)

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
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-2654.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4904");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 1333, 20, 400, 426, 863, 93);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-packaging-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/nodejs');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:18');
if ('18' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nodejs:' + module_ver);

var appstreams = {
    'nodejs:18': [
      {'reference':'nodejs-18.14.2-2.module_el9.2.0+29+de583a0b', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-18.14.2-2.module_el9.2.0+29+de583a0b', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-18.14.2-2.module_el9.2.0+29+de583a0b', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-devel-18.14.2-2.module_el9.2.0+29+de583a0b', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-docs-18.14.2-2.module_el9.2.0+29+de583a0b', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-18.14.2-2.module_el9.2.0+29+de583a0b', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-full-i18n-18.14.2-2.module_el9.2.0+29+de583a0b', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nodejs-nodemon-2.0.20-2.module_el9.2.0+29+de583a0b', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-2021.06-4.module_el9.1.0+13+d9a595ea', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nodejs-packaging-bundler-2021.06-4.module_el9.1.0+13+d9a595ea', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'npm-9.5.0-1.18.14.2.2.module_el9.2.0+29+de583a0b', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'npm-9.5.0-1.18.14.2.2.module_el9.2.0+29+de583a0b', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nodejs:18');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-devel / nodejs-docs / nodejs-full-i18n / etc');
}
