#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1880.
##

include('compat.inc');

if (description)
{
  script_id(168454);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2021-36374");

  script_name(english:"Amazon Linux 2 : ant (ALAS-2022-1880)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ant installed on the remote host is prior to 1.9.16-1. It is, therefore, affected by a vulnerability as
referenced in the ALAS2-2022-1880 advisory.

  - When reading a specially crafted ZIP archive, or a derived formats, an Apache Ant build can be made to
    allocate large amounts of memory that leads to an out of memory error, even for small inputs. This can be
    used to disrupt builds using Apache Ant. Commonly used derived formats from ZIP archives are for instance
    JAR files and many office files. Apache Ant prior to 1.9.16 and 1.10.11 were affected. (CVE-2021-36374)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1880.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-36374.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ant' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-apache-xalan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-jdepend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-jmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-jsch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-swing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ant-testutil");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'reference':'ant-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-antlr-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-bcel-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-bsf-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-log4j-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-oro-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-regexp-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-resolver-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-apache-xalan2-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-commons-logging-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-commons-net-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-javadoc-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-javamail-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-jdepend-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-jmf-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-jsch-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-junit-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-manual-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-swing-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ant-testutil-1.9.16-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ant / ant-antlr / ant-apache-bcel / etc");
}