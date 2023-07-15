#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1520.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151507);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/19");

  script_cve_id("CVE-2021-32027");
  script_xref(name:"IAVB", value:"2021-B-0036-S");
  script_xref(name:"ALAS", value:"2021-1520");

  script_name(english:"Amazon Linux AMI : postgresql96 (ALAS-2021-1520)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of postgresql96 installed on the remote host is prior to 9.6.22-1.85. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2021-1520 advisory.

  - A flaw was found in postgresql in versions before 13.3, before 12.7, before 11.12, before 10.17 and before
    9.6.22. While modifying certain SQL array values, missing bounds checks let authenticated database users
    write arbitrary bytes to a wide area of server memory. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-32027)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1520.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-32027");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql96' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32027");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'postgresql96-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-contrib-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-contrib-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-debuginfo-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-debuginfo-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-devel-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-devel-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-docs-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-docs-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-libs-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-libs-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-plperl-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-plperl-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-plpython26-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-plpython26-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-plpython27-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-plpython27-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-server-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-server-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-static-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-static-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-test-9.6.22-1.85.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql96-test-9.6.22-1.85.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql96 / postgresql96-contrib / postgresql96-debuginfo / etc");
}