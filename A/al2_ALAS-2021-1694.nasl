#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1694.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152236);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/13");

  script_cve_id("CVE-2021-33196", "CVE-2021-34558");
  script_xref(name:"ALAS", value:"2021-1694");
  script_xref(name:"IAVB", value:"2021-B-0047-S");

  script_name(english:"Amazon Linux 2 : golang (ALAS-2021-1694)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of golang installed on the remote host is prior to 1.15.14-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1694 advisory.

  - Go before 1.15.12 and 1.16.x before 1.16.5 attempts to allocate excessive memory (issue 1 of 2).
    (CVE-2021-33196)

  - The crypto/tls package of Go through 1.16.5 does not properly assert that the type of public key in an
    X.509 certificate matches the expected type when doing a RSA based key exchange, allowing a malicious TLS
    server to cause a TLS client to panic. (CVE-2021-34558)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1694.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33196");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-34558");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update golang' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'golang-1.15.14-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-1.15.14-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.15.14-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-bin-1.15.14-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-docs-1.15.14-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-misc-1.15.14-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-race-1.15.14-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-src-1.15.14-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'golang-tests-1.15.14-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang / golang-bin / golang-docs / etc");
}