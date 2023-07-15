#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-164.
##

include('compat.inc');

if (description)
{
  script_id(167030);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/05");

  script_cve_id(
    "CVE-2021-20176",
    "CVE-2021-20241",
    "CVE-2021-20246",
    "CVE-2021-20309"
  );

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-164)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-164 advisory.

  - A divide-by-zero flaw was found in ImageMagick 6.9.11-57 and 7.0.10-57 in gem.c. This flaw allows an
    attacker who submits a crafted file that is processed by ImageMagick to trigger undefined behavior through
    a division by zero. The highest threat from this vulnerability is to system availability. (CVE-2021-20176)

  - A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20241)

  - A flaw was found in ImageMagick in MagickCore/resample.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20246)

  - A flaw was found in ImageMagick in versions before 7.0.11 and before 6.9.12, where a division by zero in
    WaveImage() of MagickCore/visual-effects.c may trigger undefined behavior via a crafted image file
    submitted to an application using ImageMagick. The highest threat from this vulnerability is to system
    availability. (CVE-2021-20309)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-164.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20176.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20241.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20246.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-20309.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update ImageMagick --releasever=2022.0.20221102' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20309");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
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
    {'reference':'ImageMagick-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debugsource-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debugsource-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debugsource-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-libs-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-libs-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-libs-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-libs-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-libs-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-libs-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-debuginfo-6.9.12.48-2.amzn2022.0.6', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-debuginfo / etc");
}