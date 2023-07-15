##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1407.
##

include('compat.inc');

if (description)
{
  script_id(139087);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2019-18348", "CVE-2020-8492");
  script_xref(name:"ALAS", value:"2020-1407");

  script_name(english:"Amazon Linux AMI : python27, python34, python35, python36 (ALAS-2020-1407)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1 allows an
HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client because of
urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

  - An issue was discovered in urllib2 in Python 2.x through 2.7.17 and urllib in Python 3.x through 3.8.0.
    CRLF injection is possible if the attacker controls a url parameter, as demonstrated by the first argument
    to urllib.request.urlopen with \r
 (specifically in the host component of a URL) followed by an HTTP
    header. This is similar to the CVE-2019-9740 query string issue and the CVE-2019-9947 path string issue.
    (This is not exploitable when glibc has CVE-2016-10739 fixed.). This is fixed in: v2.7.18, v2.7.18rc1;
    v3.5.10, v3.5.10rc1; v3.6.11, v3.6.11rc1, v3.6.12; v3.7.8, v3.7.8rc1, v3.7.9; v3.8.3, v3.8.3rc1, v3.8.4,
    v3.8.4rc1, v3.8.5, v3.8.6, v3.8.6rc1. (CVE-2019-18348)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1407.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-18348.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-8492.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python27' to update your system.
 Run 'yum update python34' to update your system.
 Run 'yum update python35' to update your system.
 Run 'yum update python36' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python35-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python36-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'python27-2.7.18-1.138.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-2.7.18-1.138.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-debuginfo-2.7.18-1.138.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-debuginfo-2.7.18-1.138.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-devel-2.7.18-1.138.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-devel-2.7.18-1.138.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-libs-2.7.18-1.138.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-libs-2.7.18-1.138.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-test-2.7.18-1.138.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-test-2.7.18-1.138.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-tools-2.7.18-1.138.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python27-tools-2.7.18-1.138.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-3.4.10-1.50.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-3.4.10-1.50.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-debuginfo-3.4.10-1.50.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-debuginfo-3.4.10-1.50.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-devel-3.4.10-1.50.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-devel-3.4.10-1.50.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-libs-3.4.10-1.50.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-libs-3.4.10-1.50.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-test-3.4.10-1.50.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-test-3.4.10-1.50.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-tools-3.4.10-1.50.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python34-tools-3.4.10-1.50.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-3.5.7-1.26.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-3.5.7-1.26.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-debuginfo-3.5.7-1.26.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-debuginfo-3.5.7-1.26.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-devel-3.5.7-1.26.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-devel-3.5.7-1.26.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-libs-3.5.7-1.26.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-libs-3.5.7-1.26.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-test-3.5.7-1.26.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-test-3.5.7-1.26.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-tools-3.5.7-1.26.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python35-tools-3.5.7-1.26.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-debug-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-debug-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-debuginfo-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-debuginfo-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-devel-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-devel-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-libs-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-libs-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-test-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-test-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-tools-3.6.11-1.17.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python36-tools-3.6.11-1.17.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python27 / python27-debuginfo / python27-devel / etc");
}