#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2083.
##

include('compat.inc');

if (description)
{
  script_id(176924);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id(
    "CVE-2014-9601",
    "CVE-2016-9190",
    "CVE-2020-35653",
    "CVE-2021-28676",
    "CVE-2021-28677",
    "CVE-2021-34552"
  );

  script_name(english:"Amazon Linux 2 : python-pillow (ALAS-2023-2083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of python-pillow installed on the remote host is prior to 2.0.0-23.gitd1c6db8. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2023-2083 advisory.

  - Pillow before 2.7.0 allows remote attackers to cause a denial of service via a compressed text chunk in a
    PNG image that has a large size when it is decompressed. (CVE-2014-9601)

  - Pillow before 3.3.2 allows context-dependent attackers to execute arbitrary code by using the crafted
    image file approach, related to an Insecure Sign Extension issue affecting the ImagingNew in Storage.c
    component. (CVE-2016-9190)

  - In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the
    user-supplied stride value is trusted for buffer calculations. (CVE-2020-35653)

  - An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the
    block advance was non-zero, potentially leading to an infinite loop on load. (CVE-2021-28676)

  - An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in
    EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally
    quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use
    this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.
    (CVE-2021-28677)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2083.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2014-9601.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2016-9190.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-35653.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28676.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28677.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-34552.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python-pillow' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pillow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pillow-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pillow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pillow-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pillow-tk");
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
    {'reference':'python-pillow-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-debuginfo-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-debuginfo-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-debuginfo-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-devel-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-devel-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-devel-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-doc-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-doc-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-doc-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-sane-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-sane-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-sane-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-tk-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-tk-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-pillow-tk-2.0.0-23.gitd1c6db8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow / python-pillow-debuginfo / python-pillow-devel / etc");
}