#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1639.
##

include('compat.inc');

if (description)
{
  script_id(166356);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_cve_id(
    "CVE-2022-2257",
    "CVE-2022-2264",
    "CVE-2022-2284",
    "CVE-2022-2285",
    "CVE-2022-2286",
    "CVE-2022-2287",
    "CVE-2022-2288",
    "CVE-2022-2289",
    "CVE-2022-2304",
    "CVE-2022-2343",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2816",
    "CVE-2022-2817",
    "CVE-2022-2819",
    "CVE-2022-3037"
  );
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"Amazon Linux AMI : vim (ALAS-2022-1639)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS-2022-1639 advisory.

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2257, CVE-2022-2286,
    CVE-2022-2287)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2264, CVE-2022-2284)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0. (CVE-2022-2288)

  - Use After Free in GitHub repository vim/vim prior to 9.0. (CVE-2022-2289)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044. (CVE-2022-2343)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045. (CVE-2022-2344)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0046. (CVE-2022-2345)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0212. (CVE-2022-2816)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0213. (CVE-2022-2817)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0211. (CVE-2022-2819)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0322. (CVE-2022-3037)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1639.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2257.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2284.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2285.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2286.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2287.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2288.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2289.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2343.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2344.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2345.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2819.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3037.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update vim' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3037");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'vim-common-9.0.475-1.1.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.475-1.1.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-9.0.475-1.1.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.1.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.1.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.1.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.1.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-9.0.475-1.1.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.1.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.1.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-data / vim-debuginfo / etc");
}