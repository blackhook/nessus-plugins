#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:0321.
##

include('compat.inc');

if (description)
{
  script_id(170580);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/25");

  script_cve_id(
    "CVE-2021-44906",
    "CVE-2022-3517",
    "CVE-2022-35256",
    "CVE-2022-43548"
  );
  script_xref(name:"ALSA", value:"2023:0321");

  script_name(english:"AlmaLinux 9 : nodejs and nodejs-nodemon (ALSA-2023:0321)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:0321 advisory.

  - Minimist <=1.2.5 is vulnerable to Prototype Pollution via file index.js, function setKey() (lines 69-95).
    (CVE-2021-44906)

  - A vulnerability was found in the minimatch package. This flaw allows a Regular Expression Denial of
    Service (ReDoS) when calling the braceExpand function with specific arguments, resulting in a Denial of
    Service. (CVE-2022-3517)

  - The llhttp parser in the http module in Node v18.7.0 does not correctly handle header fields that are not
    terminated with CLRF. This may result in HTTP Request Smuggling. (CVE-2022-35256)

  - A OS Command Injection vulnerability exists in Node.js versions <14.21.1, <16.18.1, <18.12.1, <19.0.1 due
    to an insufficient IsAllowedHost check that can easily be bypassed because IsIPAddress does not properly
    check if an IP address is invalid before making DBS requests allowing rebinding attacks.The fix for this
    issue in https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32212 was incomplete and this new CVE is
    to complete the fix. (CVE-2022-43548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-0321.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1321, 350, 400, 444);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
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

var pkgs = [
    {'reference':'nodejs-16.18.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-docs-16.18.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-full-i18n-16.18.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-libs-16.18.1-3.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-nodemon-2.0.20-2.el9_1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.19.2-1.16.18.1.3.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'npm-8.19.2-1.16.18.1.3.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-docs / nodejs-full-i18n / nodejs-libs / nodejs-nodemon / etc');
}
