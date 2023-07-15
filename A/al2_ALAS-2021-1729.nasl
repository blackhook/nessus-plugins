#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1729.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155989);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-39139",
    "CVE-2021-39140",
    "CVE-2021-39141",
    "CVE-2021-39144",
    "CVE-2021-39145",
    "CVE-2021-39146",
    "CVE-2021-39147",
    "CVE-2021-39148",
    "CVE-2021-39149",
    "CVE-2021-39150",
    "CVE-2021-39151",
    "CVE-2021-39152",
    "CVE-2021-39153",
    "CVE-2021-39154"
  );
  script_xref(name:"ALAS", value:"2021-1729");
  script_xref(name:"CEA-ID", value:"CEA-2022-0035");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/31");

  script_name(english:"Amazon Linux 2 : xstream (ALAS-2021-1729)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of xstream installed on the remote host is prior to 1.3.1-16. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1729 advisory.

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. A user is only affected if using the version out of the box with
    JDK 1.7u21 or below. However, this scenario can be adjusted easily to an external Xalan that works
    regardless of the version of the Java runtime. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18
    uses no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39139)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU
    type or parallel execution of such a payload resulting in a denial of service only by manipulating the
    processed input stream. No user is affected, who followed the recommendation to setup XStream's security
    framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39140)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39141,
    CVE-2021-39145, CVE-2021-39146, CVE-2021-39147, CVE-2021-39148, CVE-2021-39149, CVE-2021-39151,
    CVE-2021-39154)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39144)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to request data from internal resources that are not publicly
    available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is
    affected, who followed the recommendation to setup XStream's security framework with a whitelist limited
    to the minimal required types. If you rely on XStream's default blacklist of the [Security
    Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version
    1.4.18. (CVE-2021-39150, CVE-2021-39152)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream, if using the version out of the box with Java runtime version 14
    to 8 or with JavaFX installed. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39153)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1729.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39139");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39140");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39141");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39144");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39145");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39147");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39148");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39149");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39150");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39151");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39152");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39153");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-39154");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update xstream' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39139");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware NSX Manager XStream unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xstream-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'xstream-1.3.1-16.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xstream-javadoc-1.3.1-16.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xstream / xstream-javadoc");
}