#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-2091.
##

include('compat.inc');

if (description)
{
  script_id(177864);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/01");

  script_cve_id("CVE-2023-34410");

  script_name(english:"Amazon Linux 2 : qt5-qtbase (ALAS-2023-2091)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of qt5-qtbase installed on the remote host is prior to 5.9.2-3. It is, therefore, affected by a
vulnerability as referenced in the ALAS2-2023-2091 advisory.

  - An issue was discovered in Qt before 5.15.15, 6.x before 6.2.9, and 6.3.x through 6.5.x before 6.5.2.
    Certificate validation for TLS does not always consider whether the root of a chain is a configured CA
    certificate. (CVE-2023-34410)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-2091.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-34410.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update qt5-qtbase' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34410");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qt5-rpm-macros");
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
    {'reference':'qt5-qtbase-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.9.2-3.amzn2.0.7', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-debuginfo-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-debuginfo-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-debuginfo-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-doc-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-doc-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-doc-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.9.2-3.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.9.2-3.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.9.2-3.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-rpm-macros-5.9.2-3.amzn2.0.7', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtbase / qt5-qtbase-common / qt5-qtbase-debuginfo / etc");
}