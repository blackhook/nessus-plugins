##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1476.
##

include('compat.inc');

if (description)
{
  script_id(144988);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-25694", "CVE-2020-25695", "CVE-2020-25696");
  script_xref(name:"ALAS", value:"2021-1476");

  script_name(english:"Amazon Linux AMI : postgresql95, postgresql96 (ALAS-2021-1476)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of postgresql95 installed on the remote host is prior to 9.5.24-1.82. The version of postgresql96 installed
on the remote host is prior to 9.6.20-1.84. It is, therefore, affected by multiple vulnerabilities as referenced in the
ALAS-2021-1476 advisory.

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

  - A flaw was found in the psql interactive terminal of PostgreSQL in versions before 13.1, before 12.5,
    before 11.10, before 10.15, before 9.6.20 and before 9.5.24. If an interactive psql session uses \gset
    when querying a compromised server, the attacker can execute arbitrary code as the operating system
    account running psql. The highest threat from this vulnerability is to data confidentiality and integrity
    as well as system availability. (CVE-2020-25696)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1476.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25694");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25695");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25696");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql95' to update your system.
 Run 'yum update postgresql96' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-test");
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
    {'reference':'postgresql95-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-contrib-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-contrib-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-debuginfo-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-debuginfo-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-devel-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-devel-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-docs-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-docs-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-libs-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-libs-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-plperl-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-plperl-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-plpython26-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-plpython26-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-plpython27-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-plpython27-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-server-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-server-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-static-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-static-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql95-test-9.5.24-1.82.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql95-test-9.5.24-1.82.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-contrib-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-contrib-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-debuginfo-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-debuginfo-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-devel-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-devel-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-docs-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-docs-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-libs-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-libs-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-plperl-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-plperl-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-plpython26-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-plpython26-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-plpython27-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-plpython27-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-server-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-server-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-static-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-static-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-test-9.6.20-1.84.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-test-9.6.20-1.84.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql95 / postgresql95-contrib / postgresql95-debuginfo / etc");
}