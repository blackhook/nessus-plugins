#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-1971.
##

include('compat.inc');

if (description)
{
  script_id(172168);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id(
    "CVE-2021-3574",
    "CVE-2021-4219",
    "CVE-2021-20224",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547"
  );

  script_name(english:"Amazon Linux 2 : ImageMagick (ALAS-2023-1971)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote host is prior to 6.9.10.68-6. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2023-1971 advisory.

  - An integer overflow issue was discovered in ImageMagick's ExportIndexQuantum() function in
    MagickCore/quantum-export.c. Function calls to GetPixelIndex() could result in values outside the range of
    representable for the 'unsigned char'. When ImageMagick processes a crafted pdf file, this could lead to
    an undefined behaviour or a crash. (CVE-2021-20224)

  - A vulnerability was found in ImageMagick-7.0.11-5, where executing a crafted file with the convert
    command, ASAN detects memory leaks. (CVE-2021-3574)

  - A flaw was found in ImageMagick. The vulnerability occurs due to improper use of open functions and leads
    to a denial of service. This flaw allows an attacker to crash the system. (CVE-2021-4219)

  - ImageMagick 7.1.0-27 is vulnerable to Buffer Overflow. (CVE-2022-28463)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned char' at coders/psd.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32545)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned long' at coders/pcl.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32546)

  - In ImageMagick, there is load of misaligned address for type 'double', which requires 8 byte alignment and
    for type 'float', which requires 4 byte alignment at MagickCore/property.c. Whenever crafted or untrusted
    input is processed by ImageMagick, this causes a negative impact to application availability or other
    problems related to undefined behavior. (CVE-2022-32547)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-1971.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20224.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3574.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4219.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-28463.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32545.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32546.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32547.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ImageMagick' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ImageMagick-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-6.amzn2.0.3', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-6.amzn2.0.3', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-6.amzn2.0.3', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}