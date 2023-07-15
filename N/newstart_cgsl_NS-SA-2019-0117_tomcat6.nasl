#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0117. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127359);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/10");

  script_cve_id(
    "CVE-2016-6816",
    "CVE-2016-8745",
    "CVE-2017-5647",
    "CVE-2017-5664",
    "CVE-2017-12615",
    "CVE-2017-12617"
  );
  script_bugtraq_id(98888);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"NewStart CGSL MAIN 4.05 : tomcat6 Multiple Vulnerabilities (NS-SA-2019-0117)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has tomcat6 packages installed that are affected by multiple
vulnerabilities:

  - It was discovered that the code that parsed the HTTP
    request line permitted invalid characters. This could be
    exploited, in conjunction with a proxy that also
    permitted the invalid characters but with a different
    interpretation, to inject data into the HTTP response.
    By manipulating the HTTP response the attacker could
    poison a web-cache, perform an XSS attack, or obtain
    sensitive information from requests other then their
    own. (CVE-2016-6816)

  - A vulnerability was discovered in Tomcat's handling of
    pipelined requests when Sendfile was used. If sendfile
    processing completed quickly, it was possible for the
    Processor to be added to the processor cache twice. This
    could lead to invalid responses or information
    disclosure. (CVE-2017-5647)

  - A vulnerability was discovered in the error page
    mechanism in Tomcat's DefaultServlet implementation. A
    crafted HTTP request could cause undesired side effects,
    possibly including the removal or replacement of the
    custom error page. (CVE-2017-5664)

  - A bug was discovered in the error handling of the send
    file code for the NIO HTTP connector. This led to the
    current Processor object being added to the Processor
    cache multiple times allowing information leakage
    between requests including, and not limited to, session
    ID and the response body. (CVE-2016-8745)

  - A vulnerability was discovered in Tomcat where if a
    servlet context was configured with readonly=false and
    HTTP PUT requests were allowed, an attacker could upload
    a JSP file to that context and achieve code execution.
    (CVE-2017-12617, CVE-2017-12615)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0117");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tomcat6 packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "tomcat6-6.0.24-111.el6_9",
    "tomcat6-el-2.1-api-6.0.24-111.el6_9",
    "tomcat6-jsp-2.1-api-6.0.24-111.el6_9",
    "tomcat6-lib-6.0.24-111.el6_9",
    "tomcat6-servlet-2.5-api-6.0.24-111.el6_9"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6");
}
