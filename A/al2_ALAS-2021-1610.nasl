##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1610.
##

include('compat.inc');

if (description)
{
  script_id(146623);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"ALAS", value:"2021-1610");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux 2 : perl (ALAS-2021-1610)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of perl installed on the remote host is prior to 5.16.3-299. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1610 advisory.

  - Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular
    expression quantifiers have an integer overflow. (CVE-2020-10543)

  - Perl before 5.30.3 has an integer overflow related to mishandling of a PL_regkind[OP(n)] == NOTHING
    situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction
    injection. (CVE-2020-10878)

  - regcomp.c in Perl before 5.30.3 allows a buffer overflow via a crafted regular expression because of
    recursive S_study_chunk calls. (CVE-2020-12723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1610.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10543");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10878");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-12723");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update perl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'perl-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-core-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-core-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-core-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-CPAN-1.9800-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-debuginfo-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-debuginfo-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-debuginfo-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-devel-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-devel-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-devel-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-ExtUtils-CBuilder-0.28.2.6-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-ExtUtils-Embed-1.30-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-ExtUtils-Install-1.58-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-IO-Zlib-1.10-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-libs-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-libs-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-libs-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-Locale-Maketext-Simple-0.21-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-macros-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-macros-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-macros-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-Module-CoreList-2.76.02-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-Module-Loaded-0.08-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-Object-Accessor-0.42-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-Package-Constants-0.02-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-Pod-Escapes-1.04-299.amzn2.0.1', 'release':'AL2'},
    {'reference':'perl-tests-5.16.3-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-tests-5.16.3-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-tests-5.16.3-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-Time-Piece-1.20.1-299.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-Time-Piece-1.20.1-299.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-Time-Piece-1.20.1-299.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CPAN / perl-ExtUtils-CBuilder / etc");
}