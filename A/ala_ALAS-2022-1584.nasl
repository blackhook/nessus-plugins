#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1584.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160333);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/13");

  script_cve_id(
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23943"
  );
  script_xref(name:"IAVA", value:"2022-A-0124-S");
  script_xref(name:"ALAS", value:"2022-1584");

  script_name(english:"Amazon Linux AMI : httpd24 (ALAS-2022-1584)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of httpd24 installed on the remote host is prior to 2.4.53-1.96. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2022-1584 advisory.

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap
    memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and
    prior versions. (CVE-2022-23943)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1584.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22719.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22721.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23943.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update httpd24' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'httpd24-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-debuginfo-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-debuginfo-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-devel-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-devel-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-manual-2.4.53-1.96.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-tools-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd24-tools-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_ldap-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_ldap-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_md-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_md-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_proxy_html-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_proxy_html-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_session-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_session-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_ssl-2.4.53-1.96.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod24_ssl-2.4.53-1.96.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd24 / httpd24-debuginfo / httpd24-devel / etc");
}