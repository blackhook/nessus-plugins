#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-063.
##

include('compat.inc');

if (description)
{
  script_id(173077);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-24407");

  script_name(english:"Amazon Linux 2023 : cyrus-sasl, cyrus-sasl-devel, cyrus-sasl-gs2 (ALAS2023-2023-063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2023-2023-063 advisory.

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-063.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-24407.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update cyrus-sasl --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-gs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-gs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-gssapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-lib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-md5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-ntlm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-plain-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-scram");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-scram-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cyrus-sasl-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'cyrus-sasl-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debugsource-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debugsource-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-debugsource-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-devel-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gs2-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-gssapi-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ldap-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-lib-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-md5-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-ntlm-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-plain-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-scram-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cyrus-sasl-sql-debuginfo-2.1.27-18.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-sasl / cyrus-sasl-debuginfo / cyrus-sasl-debugsource / etc");
}