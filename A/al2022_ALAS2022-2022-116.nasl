#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-116.
##

include('compat.inc');

if (description)
{
  script_id(164766);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_cve_id(
    "CVE-2021-3770",
    "CVE-2022-0554",
    "CVE-2022-0572",
    "CVE-2022-0629",
    "CVE-2022-1616",
    "CVE-2022-1619",
    "CVE-2022-1620",
    "CVE-2022-1621",
    "CVE-2022-1629",
    "CVE-2022-1674",
    "CVE-2022-1720",
    "CVE-2022-1725",
    "CVE-2022-1733",
    "CVE-2022-1735",
    "CVE-2022-1769",
    "CVE-2022-1771",
    "CVE-2022-1785",
    "CVE-2022-1796",
    "CVE-2022-1851",
    "CVE-2022-1886",
    "CVE-2022-1897",
    "CVE-2022-1898",
    "CVE-2022-1927",
    "CVE-2022-1942",
    "CVE-2022-1968",
    "CVE-2022-2000",
    "CVE-2022-2042",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2129",
    "CVE-2022-2175",
    "CVE-2022-2182",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2207",
    "CVE-2022-2208",
    "CVE-2022-2210",
    "CVE-2022-2231"
  );
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-116)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-116 advisory.

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977. (CVE-2022-1785)

  - Use After Free in GitHub repository vim/vim prior to 8.2.4979. (CVE-2022-1796)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1851, CVE-2022-2126,
    CVE-2022-2183, CVE-2022-2206)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-1886, CVE-2022-1942,
    CVE-2022-2125, CVE-2022-2182, CVE-2022-2207)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-1897, CVE-2022-2000,
    CVE-2022-2129, CVE-2022-2210)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-1898, CVE-2022-1968, CVE-2022-2042)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1927, CVE-2022-2124, CVE-2022-2175)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163. (CVE-2022-2208)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2. (CVE-2022-2231)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-116.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1785.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1796.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1886.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1897.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1898.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1942.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1968.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2125.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2126.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2175.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2182.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2183.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2207.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2210.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2231.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220719 vim' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2210");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-default-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
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

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'vim-common-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-8.2.5172-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-default-editor-8.2.5172-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-8.2.5172-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-8.2.5172-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-common-debuginfo / vim-data / etc");
}