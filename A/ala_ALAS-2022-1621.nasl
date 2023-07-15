##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1621.
##

include('compat.inc');

if (description)
{
  script_id(163861);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/05");

  script_cve_id(
    "CVE-2022-20770",
    "CVE-2022-20771",
    "CVE-2022-20785",
    "CVE-2022-20796"
  );

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2022-1621)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of clamav installed on the remote host is prior to 0.103.6-1.49. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2022-1621 advisory.

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in CHM file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20770)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in the TIFF file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20771)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in HTML file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20785)

  - On May 4, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in Clam AntiVirus (ClamAV) versions 0.103.4,
    0.103.5, 0.104.1, and 0.104.2 could allow an authenticated, local attacker to cause a denial of service
    condition on an affected device. For a description of this vulnerability, see the ClamAV blog.
    (CVE-2022-20796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-20770.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-20771.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-20785.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-20796.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update clamav' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'clamav-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-data-0.103.6-1.49.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-db-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-db-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-debuginfo-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-debuginfo-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-devel-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-devel-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-filesystem-0.103.6-1.49.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-lib-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-lib-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-milter-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-milter-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-update-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamav-update-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamd-0.103.6-1.49.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clamd-0.103.6-1.49.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-data / clamav-db / etc");
}