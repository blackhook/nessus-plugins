#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1530.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153170);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/09");

  script_cve_id("CVE-2020-36328");
  script_xref(name:"ALAS", value:"2021-1530");

  script_name(english:"Amazon Linux AMI : libwebp (ALAS-2021-1530)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of libwebp installed on the remote host is prior to 0.3.0-10.7. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2021-1530 advisory.

  - A flaw was found in libwebp in versions before 1.0.1. A heap-based buffer overflow in function
    WebPDecodeRGBInto is possible due to an invalid check for buffer size. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-36328)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1530.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36328");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libwebp' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36328");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwebp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwebp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwebp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwebp-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwebp-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'libwebp-0.3.0-10.7.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-0.3.0-10.7.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-debuginfo-0.3.0-10.7.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-debuginfo-0.3.0-10.7.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-devel-0.3.0-10.7.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-devel-0.3.0-10.7.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-java-0.3.0-10.7.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-java-0.3.0-10.7.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-tools-0.3.0-10.7.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwebp-tools-0.3.0-10.7.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwebp / libwebp-debuginfo / libwebp-devel / etc");
}