#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0105. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127336);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : java-1.7.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0105)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has java-1.7.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - It was found that the JAXP component of OpenJDK failed
    to correctly enforce parse tree size limits when parsing
    XML document. An attacker able to make a Java
    application parse a specially crafted XML document could
    use this flaw to make it consume an excessive amount of
    CPU and memory. (CVE-2017-3526)

  - An untrusted library search path flaw was found in the
    JCE component of OpenJDK. A local attacker could
    possibly use this flaw to cause a Java application using
    JCE to load an attacker-controlled library and hence
    escalate their privileges. (CVE-2017-3511)

  - It was discovered that the HTTP client implementation in
    the Networking component of OpenJDK could cache and re-
    use an NTLM authenticated connection in a different
    security context. A remote attacker could possibly use
    this flaw to make a Java application perform HTTP
    requests authenticated with credentials of a different
    user. (CVE-2017-3509)

  - A newline injection flaw was discovered in the SMTP
    client implementation in the Networking component in
    OpenJDK. A remote attacker could possibly use this flaw
    to manipulate SMTP connections established by a Java
    application. (CVE-2017-3544)

  - It was discovered that the Security component of OpenJDK
    did not allow users to restrict the set of algorithms
    allowed for Jar integrity verification. This flaw could
    allow an attacker to modify content of the Jar file that
    used weak signing key or hash algorithm. (CVE-2017-3539)

  - A newline injection flaw was discovered in the FTP
    client implementation in the Networking component in
    OpenJDK. A remote attacker could possibly use this flaw
    to manipulate FTP connections established by a Java
    application. (CVE-2017-3533)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0105");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.7.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3544");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-3511");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el6_9",
    "java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.el6_9"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk");
}
