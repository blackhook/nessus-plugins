##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1441.
##

include('compat.inc');

if (description)
{
  script_id(141992);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2019-10208");
  script_xref(name:"ALAS", value:"2020-1441");

  script_name(english:"Amazon Linux AMI : postgresql94 (ALAS-2020-1441)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2020-1441 advisory.

  - A flaw was discovered in postgresql versions 9.4.x before 9.4.24, 9.5.x before 9.5.19, 9.6.x before
    9.6.15, 10.x before 10.10 and 11.x before 11.5 where arbitrary SQL statements can be executed given a
    suitable SECURITY DEFINER function. An attacker, with EXECUTE permission on the function, can execute
    arbitrary SQL as the owner of the function. (CVE-2019-10208)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1441.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10208");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql94' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10208");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-test");
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
    {'reference':'postgresql94-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-contrib-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-contrib-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-debuginfo-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-debuginfo-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-devel-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-devel-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-docs-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-docs-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-libs-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-libs-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-plperl-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-plperl-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-plpython26-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-plpython26-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-plpython27-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-plpython27-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-server-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-server-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'postgresql94-test-9.4.26-1.77.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'postgresql94-test-9.4.26-1.77.amzn1', 'cpu':'x86_64', 'release':'ALA'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql94 / postgresql94-contrib / postgresql94-debuginfo / etc");
}