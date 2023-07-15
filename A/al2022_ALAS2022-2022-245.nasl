#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-245.
##

include('compat.inc');

if (description)
{
  script_id(168563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/09");

  script_cve_id(
    "CVE-2022-32081",
    "CVE-2022-32082",
    "CVE-2022-32084",
    "CVE-2022-32089"
  );

  script_name(english:"Amazon Linux 2022 : mariadb105 (ALAS2022-2022-245)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of mariadb105 installed on the remote host is prior to 10.5.16-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2022-2022-245 advisory.

  - MariaDB v10.4 to v10.7 was discovered to contain an use-after-poison in prepare_inplace_add_virtual at
    /storage/innobase/handler/handler0alter.cc. (CVE-2022-32081)

  - MariaDB v10.5 to v10.7 was discovered to contain an assertion failure at table->get_ref_count() == 0 in
    dict0dict.cc. (CVE-2022-32082)

  - MariaDB v10.2 to v10.7 was discovered to contain a segmentation fault via the component sub_select.
    (CVE-2022-32084)

  - MariaDB v10.5 to v10.7 was discovered to contain a segmentation fault via the component
    st_select_lex_unit::exclude_level. (CVE-2022-32089)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-245.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32081.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32082.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32084.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32089.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update mariadb105' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32081");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-backup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-connect-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-connect-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-cracklib-password-check-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-gssapi-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-oqgraph-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-rocksdb-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-rocksdb-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-sphinx-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-sphinx-engine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mariadb105-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
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
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'mariadb105-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-backup-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-common-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-common-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-common-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-connect-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-cracklib-password-check-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debugsource-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debugsource-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-debugsource-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-devel-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-devel-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-devel-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-errmsg-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-errmsg-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-errmsg-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-gssapi-server-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-oqgraph-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-pam-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-rocksdb-engine-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-rocksdb-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-server-utils-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-sphinx-engine-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mariadb105-test-debuginfo-10.5.16-1.amzn2022.0.5', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb105 / mariadb105-backup / mariadb105-backup-debuginfo / etc");
}