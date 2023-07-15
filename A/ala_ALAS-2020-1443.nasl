##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1443.
##

include('compat.inc');

if (description)
{
  script_id(141979);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id(
    "CVE-2019-10130",
    "CVE-2019-10208",
    "CVE-2020-1720",
    "CVE-2020-14350"
  );
  script_bugtraq_id(108452);
  script_xref(name:"ALAS", value:"2020-1443");

  script_name(english:"Amazon Linux AMI : postgresql96 (ALAS-2020-1443)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1443 advisory.

  - A vulnerability was found in PostgreSQL versions 11.x up to excluding 11.3, 10.x up to excluding 10.8,
    9.6.x up to, excluding 9.6.13, 9.5.x up to, excluding 9.5.17. PostgreSQL maintains column statistics for
    tables. Certain statistics, such as histograms and lists of most common values, contain values taken from
    the column. PostgreSQL does not evaluate row security policies before consulting those statistics during
    query planning; an attacker can exploit this to read the most common values of certain columns. Affected
    columns are those for which the attacker has SELECT privilege and for which, in an ordinary query, row-
    level security prunes the set of rows visible to the attacker. (CVE-2019-10130)

  - A flaw was discovered in postgresql versions 9.4.x before 9.4.24, 9.5.x before 9.5.19, 9.6.x before
    9.6.15, 10.x before 10.10 and 11.x before 11.5 where arbitrary SQL statements can be executed given a
    suitable SECURITY DEFINER function. An attacker, with EXECUTE permission on the function, can execute
    arbitrary SQL as the owner of the function. (CVE-2019-10208)

  - It was found that some PostgreSQL extensions did not use search_path safely in their installation script.
    An attacker with sufficient privileges could use this flaw to trick an administrator into executing a
    specially crafted script, during the installation or update of such extension. This affects PostgreSQL
    versions before 12.4, before 11.9, before 10.14, before 9.6.19, and before 9.5.23. (CVE-2020-14350)

  - A flaw was found in PostgreSQL's ALTER ... DEPENDS ON EXTENSION, where sub-commands did not perform
    authorization checks. An authenticated attacker could use this flaw in certain configurations to perform
    drop objects such as function, triggers, et al., leading to database corruption. This issue affects
    PostgreSQL versions before 12.2, before 11.7, before 10.12 and before 9.6.17. (CVE-2020-1720)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1443.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10130");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10208");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14350");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-1720");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql96' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10208");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'postgresql96-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-contrib-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-contrib-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-debuginfo-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-debuginfo-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-devel-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-devel-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-docs-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-docs-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-libs-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-libs-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-plperl-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-plperl-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-plpython26-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-plpython26-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-plpython27-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-plpython27-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-server-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-server-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-static-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-static-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql96-test-9.6.19-1.83.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql96-test-9.6.19-1.83.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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