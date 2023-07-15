#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-214.
##

include('compat.inc');

if (description)
{
  script_id(168555);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/09");

  script_cve_id(
    "CVE-2021-22959",
    "CVE-2021-22960",
    "CVE-2021-43616",
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2022-21824"
  );

  script_name(english:"Amazon Linux 2022 : nodejs (ALAS2022-2022-214)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of nodejs installed on the remote host is prior to 18.4.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2022-2022-214 advisory.

  - The parser in accepts requests with a space (SP) right after the header name before the colon. This can
    lead to HTTP Request Smuggling (HRS) in llhttp < v2.1.4 and < v6.0.6. (CVE-2021-22959)

  - The parse function in llhttp < 2.1.4 and < 6.0.6. ignores chunk extensions when parsing the body of
    chunked requests. This leads to HTTP Request Smuggling (HRS) under certain conditions. (CVE-2021-22960)

  - ** DISPUTED ** The npm ci command in npm 7.x and 8.x through 8.1.3 proceeds with an installation even if
    dependency information in package-lock.json differs from package.json. This behavior is inconsistent with
    the documentation, and makes it easier for attackers to install malware that was supposed to have been
    blocked by an exact version match requirement in package-lock.json. NOTE: The npm team believes this is
    not a vulnerability. It would require someone to socially engineer package.json which has different
    dependencies than package-lock.json. That user would have to have file system or write access to change
    dependencies. The npm team states preventing malicious actors from socially engineering or gaining file
    system access is outside the scope of the npm CLI. (CVE-2021-43616)

  - Accepting arbitrary Subject Alternative Name (SAN) types, unless a PKI is specifically defined to use a
    particular SAN type, can result in bypassing name-constrained intermediates. Node.js < 12.22.9, < 14.18.3,
    < 16.13.2, and < 17.3.1 was accepting URI SAN types, which PKIs are often not defined to use.
    Additionally, when a protocol allows URI SANs, Node.js did not match the URI correctly.Versions of Node.js
    with the fix for this disable the URI SAN type when checking a certificate against a hostname. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44531)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 converts SANs (Subject Alternative Names) to a
    string format. It uses this string to check peer certificates against hostnames when validating
    connections. The string format was subject to an injection vulnerability when name constraints were used
    within a certificate chain, allowing the bypass of these name constraints.Versions of Node.js with the fix
    for this escape SANs containing the problematic characters in order to prevent the injection. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44532)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 did not handle multi-value Relative Distinguished
    Names correctly. Attackers could craft certificate subjects containing a single-value Relative
    Distinguished Name that would be interpreted as a multi-value Relative Distinguished Name, for example, in
    order to inject a Common Name that would allow bypassing the certificate subject verification.Affected
    versions of Node.js that do not accept multi-value Relative Distinguished Names and are thus not
    vulnerable to such attacks themselves. However, third-party code that uses node's ambiguous presentation
    of certificate subjects may be vulnerable. (CVE-2021-44533)

  - Due to the formatting logic of the console.table() function it was not safe to allow user controlled
    input to be passed to the properties parameter while simultaneously passing a plain object with at least
    one property as the first parameter, which could be __proto__. The prototype pollution has very limited
    control, in that it only allows an empty string to be assigned to numerical keys of the object
    prototype.Node.js >= 12.22.9, >= 14.18.3, >= 16.13.2, and >= 17.3.1 use a null protoype for the object
    these properties are being assigned to. (CVE-2022-21824)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-214.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-22959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-22960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-43616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44531.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44532.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44533.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21824.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update nodejs' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43616");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:npm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:v8-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'nodejs-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debuginfo-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debuginfo-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debuginfo-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debugsource-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debugsource-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-debugsource-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-devel-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-devel-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-devel-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-docs-18.4.0-1.amzn2022.0.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-full-i18n-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-full-i18n-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-full-i18n-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-debuginfo-18.4.0-1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-debuginfo-18.4.0-1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-libs-debuginfo-18.4.0-1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.12.1-1.18.4.0.1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.12.1-1.18.4.0.1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-8.12.1-1.18.4.0.1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-devel-10.2.154.4-1.18.4.0.1.amzn2022.0.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-devel-10.2.154.4-1.18.4.0.1.amzn2022.0.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-devel-10.2.154.4-1.18.4.0.1.amzn2022.0.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / etc");
}