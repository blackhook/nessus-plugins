#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1519.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151513);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2019-10208", "CVE-2020-25694", "CVE-2020-25695");
  script_xref(name:"IAVB", value:"2019-B-0072-S");
  script_xref(name:"IAVB", value:"2020-B-0069-S");
  script_xref(name:"ALAS", value:"2021-1519");

  script_name(english:"Amazon Linux AMI : postgresql92 (ALAS-2021-1519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of postgresql92 installed on the remote host is prior to 9.2.24-3.67. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2021-1519 advisory.

  - A flaw was discovered in postgresql versions 9.4.x before 9.4.24, 9.5.x before 9.5.19, 9.6.x before
    9.6.15, 10.x before 10.10 and 11.x before 11.5 where arbitrary SQL statements can be executed given a
    suitable SECURITY DEFINER function. An attacker, with EXECUTE permission on the function, can execute
    arbitrary SQL as the owner of the function. (CVE-2019-10208)

  - A flaw was found in PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before
    9.6.20 and before 9.5.24. If a client application that creates additional database connections only reuses
    the basic connection parameters while dropping security-relevant parameters, an opportunity for a man-in-
    the-middle attack, or the ability to observe clear-text transmissions, could exist. The highest threat
    from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-25694)

  - A flaw was found in PostgreSQL versions before 13.1, before 12.5, before 11.10, before 10.15, before
    9.6.20 and before 9.5.24. An attacker having permission to create non-temporary objects in at least one
    schema can execute arbitrary SQL functions under the identity of a superuser. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-25695)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1519.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10208");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25694");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25695");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql92' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25694");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-server-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'postgresql92-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-contrib-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-contrib-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-debuginfo-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-debuginfo-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-devel-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-devel-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-docs-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-docs-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-libs-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-libs-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-plperl-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-plperl-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-plpython26-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-plpython26-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-plpython27-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-plpython27-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-pltcl-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-pltcl-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-server-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-server-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-server-compat-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-server-compat-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-test-9.2.24-3.67.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql92-test-9.2.24-3.67.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql92 / postgresql92-contrib / postgresql92-debuginfo / etc");
}