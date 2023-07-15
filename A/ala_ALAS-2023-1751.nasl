#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1751.
##

include('compat.inc');

if (description)
{
  script_id(176764);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/07");

  script_cve_id("CVE-2023-31484");

  script_name(english:"Amazon Linux AMI : perl (ALAS-2023-1751)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of perl installed on the remote host is prior to 5.16.3-294.44. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2023-1751 advisory.

  - CPAN.pm before 2.35 does not verify TLS certificates when downloading distributions over HTTPS.
    (CVE-2023-31484)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1751.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31484.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update perl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'perl-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-core-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-core-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-CPAN-1.9800-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debuginfo-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debuginfo-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-devel-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-devel-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-CBuilder-0.28.2.6-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Embed-1.30-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Install-1.58-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Zlib-1.10-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-libs-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Locale-Maketext-Simple-0.21-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-macros-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-macros-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-CoreList-2.76.02-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Loaded-0.08-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Object-Accessor-0.42-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Package-Constants-0.02-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Pod-Escapes-1.04-294.44.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-tests-5.16.3-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-tests-5.16.3-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.20.1-294.44.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.20.1-294.44.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CPAN / perl-ExtUtils-CBuilder / etc");
}