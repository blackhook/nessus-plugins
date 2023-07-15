#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2022-1562.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156871);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id("CVE-2017-5645", "CVE-2019-17571", "CVE-2021-4104");
  script_xref(name:"IAVA", value:"2019-A-0128");
  script_xref(name:"IAVA", value:"2020-A-0140");
  script_xref(name:"IAVA", value:"2020-A-0008-S");
  script_xref(name:"IAVA", value:"2020-A-0326");
  script_xref(name:"IAVA", value:"2020-A-0324");
  script_xref(name:"IAVA", value:"2018-A-0229-S");
  script_xref(name:"IAVA", value:"2018-A-0118-S");
  script_xref(name:"IAVA", value:"2019-A-0256-S");
  script_xref(name:"IAVA", value:"2018-A-0336-S");
  script_xref(name:"IAVA", value:"2019-A-0021-S");
  script_xref(name:"IAVA", value:"2019-A-0025-S");
  script_xref(name:"IAVA", value:"2018-A-0117-S");
  script_xref(name:"IAVA", value:"2018-A-0226-S");
  script_xref(name:"IAVA", value:"2018-A-0225-S");
  script_xref(name:"IAVA", value:"2018-A-0335-S");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"0001-A-0650");
  script_xref(name:"IAVA", value:"2018-A-0030-S");
  script_xref(name:"ALAS", value:"2022-1562");

  script_name(english:"Amazon Linux AMI : log4j (ALAS-2022-1562)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of log4j installed on the remote host is prior to 1.2.17-16.12. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2022-1562 advisory.

  - In Apache Log4j 2.x before 2.8.2, when using the TCP socket server or UDP socket server to receive
    serialized log events from another application, a specially crafted binary payload can be sent that, when
    deserialized, can execute arbitrary code. (CVE-2017-5645)

  - Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted data
    which can be exploited to remotely execute arbitrary code when combined with a deserialization gadget when
    listening to untrusted network traffic for log data. This affects Log4j versions up to 1.2 up to 1.2.17.
    (CVE-2019-17571)

  - JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write
    access to the Log4j configuration. The attacker can provide TopicBindingName and
    TopicConnectionFactoryBindingName configurations causing JMSAppender to perform JNDI requests that result
    in remote code execution in a similar fashion to CVE-2021-44228. Note this issue only affects Log4j 1.2
    when specifically configured to use JMSAppender, which is not the default. Apache Log4j 1.2 reached end of
    life in August 2015. Users should upgrade to Log4j 2 as it addresses numerous other issues from the
    previous versions. (CVE-2021-4104)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2022-1562.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-5645.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-17571.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4104.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update log4j' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:log4j-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:log4j-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'log4j-1.2.17-16.12.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'log4j-javadoc-1.2.17-16.12.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'log4j-manual-1.2.17-16.12.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "log4j / log4j-javadoc / log4j-manual");
}