#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-149.
##

include('compat.inc');

if (description)
{
  script_id(166120);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/14");

  script_cve_id("CVE-2021-28544", "CVE-2022-24070");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-149)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-149 advisory.

  - Apache Subversion SVN authz protected copyfrom paths regression Subversion servers reveal 'copyfrom' paths
    that should be hidden according to configured path-based authorization (authz) rules. When a node has been
    copied from a protected location, users with access to the copy can see the 'copyfrom' path of the
    original. This also reveals the fact that the node was copied. Only the 'copyfrom' path is revealed; not
    its contents. Both httpd and svnserve servers are vulnerable. (CVE-2021-28544)

  - Subversion's mod_dav_svn is vulnerable to memory corruption. While looking up path-based authorization
    rules, mod_dav_svn servers may attempt to use memory which has already been freed. Affected Subversion
    mod_dav_svn servers 1.10.0 through 1.14.1 (inclusive). Servers that do not use mod_dav_svn are not
    affected. (CVE-2022-24070)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-149.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28544.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24070.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update subversion --releasever=2022.0.20221012' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28544");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools-debuginfo");
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

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'python3-subversion-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-subversion-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-subversion-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-subversion-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-subversion-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-subversion-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-debugsource-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-debugsource-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-debugsource-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-devel-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-devel-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-devel-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-devel-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-devel-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-devel-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-javahl-1.14.2-5.amzn2022.0.1', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-libs-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-libs-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-libs-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-libs-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-libs-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-libs-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-perl-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-perl-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-perl-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-perl-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-perl-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-perl-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-tools-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-tools-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-tools-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-tools-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-tools-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'subversion-tools-debuginfo-1.14.2-5.amzn2022.0.1', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-subversion / python3-subversion-debuginfo / subversion / etc");
}