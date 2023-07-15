#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:1743.
##

include('compat.inc');

if (description)
{
  script_id(174795);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/26");

  script_cve_id(
    "CVE-2021-35065",
    "CVE-2022-3517",
    "CVE-2022-4904",
    "CVE-2022-25881",
    "CVE-2022-38900",
    "CVE-2023-23918",
    "CVE-2023-23920"
  );
  script_xref(name:"RLSA", value:"2023:1743");

  script_name(english:"Rocky Linux 8 : nodejs:14 (RLSA-2023:1743)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:1743 advisory.

  - The glob-parent package before 6.0.1 for Node.js allows ReDoS (regular expression denial of service)
    attacks against the enclosure regular expression. (CVE-2021-35065)

  - This affects versions of the package http-cache-semantics before 4.1.1. The issue can be exploited via
    malicious request header values sent to a server, when that server reads the cache policy from the request
    using this library. (CVE-2022-25881)

  - A vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of
    Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of
    Service. (CVE-2022-3517)

  - decode-uri-component 0.2.0 is vulnerable to Improper Input Validation resulting in DoS. (CVE-2022-38900)

  - A flaw was found in the c-ares package. The ares_set_sortlist is missing checks about the validity of the
    input string, which allows a possible arbitrary length stack overflow. This issue may cause a denial of
    service or a limited impact on confidentiality and integrity. (CVE-2022-4904)

  - A privilege escalation vulnerability exists in Node.js <19.6.1, <18.14.1, <16.19.1 and <14.21.3 that made
    it possible to bypass the experimental Permissions (https://nodejs.org/api/permissions.html) feature in
    Node.js and access non authorized modules by using process.mainModule.require(). This only affects users
    who had enabled the experimental permissions option with --experimental-policy. (CVE-2023-23918)

  - An untrusted search path vulnerability exists in Node.js. <19.6.1, <18.14.1, <16.19.1, and <14.21.3 that
    could allow an attacker to search and potentially load ICU data when running with elevated privileges.
    (CVE-2023-23920)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:1743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2134609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2156324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2168631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2170644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2172217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2175826");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4904");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'nodejs-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debuginfo-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debuginfo-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debugsource-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debugsource-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-devel-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-devel-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-docs-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-full-i18n-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-full-i18n-14.21.3-1.module+el8.7.0+1183+c2c35f0a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-nodemon-2.0.20-3.module+el8.7.0+1178+d52dba78', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-packaging-23-3.module+el8.7.0+1071+4bdda2a8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'npm-6.14.18-1.14.21.3.1.module+el8.7.0+1183+c2c35f0a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'npm-6.14.18-1.14.21.3.1.module+el8.7.0+1183+c2c35f0a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / etc');
}
