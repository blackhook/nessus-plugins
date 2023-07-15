#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-155.
##

include('compat.inc');

if (description)
{
  script_id(166352);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_cve_id(
    "CVE-2021-3770",
    "CVE-2021-3903",
    "CVE-2021-3927",
    "CVE-2021-3928",
    "CVE-2021-3968",
    "CVE-2021-3973",
    "CVE-2021-3974",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4069",
    "CVE-2021-4136",
    "CVE-2021-4166",
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0128",
    "CVE-2022-0156",
    "CVE-2022-0158",
    "CVE-2022-0213",
    "CVE-2022-0261",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0392",
    "CVE-2022-0393",
    "CVE-2022-0407",
    "CVE-2022-0408",
    "CVE-2022-0413",
    "CVE-2022-0417",
    "CVE-2022-0443",
    "CVE-2022-0554",
    "CVE-2022-0572",
    "CVE-2022-0629",
    "CVE-2022-0685",
    "CVE-2022-0696",
    "CVE-2022-0714",
    "CVE-2022-0729",
    "CVE-2022-0943",
    "CVE-2022-1154",
    "CVE-2022-1160",
    "CVE-2022-1381",
    "CVE-2022-1420",
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
    "CVE-2022-2231",
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
    "CVE-2022-2522",
    "CVE-2022-2571",
    "CVE-2022-2580",
    "CVE-2022-2581",
    "CVE-2022-2598",
    "CVE-2022-2816",
    "CVE-2022-2817",
    "CVE-2022-2819",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2862",
    "CVE-2022-2874",
    "CVE-2022-2889",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-2980",
    "CVE-2022-2982",
    "CVE-2022-3016",
    "CVE-2022-3037",
    "CVE-2022-3099",
    "CVE-2022-3134",
    "CVE-2022-3153"
  );
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-155 advisory.

  - Use After Free in GitHub repository vim/vim prior to 9.0.0360. (CVE-2022-3099)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0389. (CVE-2022-3134)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0404. (CVE-2022-3153)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-155.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3153.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update vim --releasever=2022.0.20221019' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3973");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

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
    {'reference':'vim-common-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-9.0.475-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-default-editor-9.0.475-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-9.0.475-1.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.475-1.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-common-debuginfo / vim-data / etc");
}