#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-044.
##

include('compat.inc');

if (description)
{
  script_id(164736);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/06");

  script_cve_id("CVE-2022-23181");

  script_name(english:"Amazon Linux 2022 :  (ALAS2022-2022-044)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2022-2022-044 advisory.

  - The fix for bug CVE-2020-9484 introduced a time of check, time of use vulnerability into Apache Tomcat
    10.1.0-M1 to 10.1.0-M8, 10.0.0-M5 to 10.0.14, 9.0.35 to 9.0.56 and 8.5.55 to 8.5.73 that allowed a local
    attacker to perform actions with the privileges of the user that the Tomcat process is using. This issue
    is only exploitable when Tomcat is configured to persist sessions using the FileStore. (CVE-2022-23181)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-044.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23181.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220419 tomcat' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-servlet-4.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat-webapps");
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
    {'reference':'tomcat-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-admin-webapps-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-docs-webapp-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-el-3.0-api-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-jsp-2.3-api-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-jsvc-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-lib-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-servlet-4.0-api-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tomcat-webapps-9.0.59-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}