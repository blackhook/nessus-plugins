#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-1973.
##

include('compat.inc');

if (description)
{
  script_id(172166);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2022-1941");

  script_name(english:"Amazon Linux 2 : protobuf (ALAS-2023-1973)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of protobuf installed on the remote host is prior to 2.5.0-8. It is, therefore, affected by a vulnerability
as referenced in the ALAS2-2023-1973 advisory.

  - A parsing vulnerability for the MessageSet type in the ProtocolBuffers versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 3.21.5 for protobuf-cpp, and versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 4.21.5 for protobuf-python can lead to out of memory failures.
    A specially crafted message with multiple key-value per elements creates parsing issues, and can lead to a
    Denial of Service against services receiving unsanitized input. We recommend upgrading to versions 3.18.3,
    3.19.5, 3.20.2, 3.21.6 for protobuf-cpp and 3.18.3, 3.19.5, 3.20.2, 4.21.6 for protobuf-python. Versions
    for 3.16 and 3.17 are no longer updated. (CVE-2022-1941)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-1973.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1941.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update protobuf' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-lite-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:protobuf-vim");
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
    {'reference':'protobuf-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-compiler-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-compiler-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-compiler-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-debuginfo-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-debuginfo-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-debuginfo-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-devel-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-devel-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-devel-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-emacs-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-emacs-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-emacs-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-emacs-el-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-emacs-el-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-emacs-el-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-java-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-java-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-java-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-javadoc-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-javadoc-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-javadoc-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-devel-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-devel-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-devel-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-static-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-static-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-lite-static-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-python-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-python-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-python-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-static-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-static-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-static-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-vim-2.5.0-8.amzn2.0.4', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-vim-2.5.0-8.amzn2.0.4', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'protobuf-vim-2.5.0-8.amzn2.0.4', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "protobuf / protobuf-compiler / protobuf-debuginfo / etc");
}