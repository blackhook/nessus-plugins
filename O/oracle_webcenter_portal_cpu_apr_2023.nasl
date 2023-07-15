#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174540);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-36033",
    "CVE-2022-40151",
    "CVE-2022-41881",
    "CVE-2022-42003"
  );
  script_xref(name:"IAVA", value:"2023-A-0210");

  script_name(english:"Oracle WebCenter Portal Multiple Vulnerabilities (April 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the April 2023
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities:

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
    (Netty)).  Supported versions that are affected are 12.2.1.4.0. Netty project is an event-driven 
    asynchronous network application framework. In versions prior to 4.1.86.Final, a stack overflow error can be 
    raised when parsing a malformed crafted message due to an infinite recursion. This issue is patched in 
    version 4.1.86.Final. There is no workaround, except using a custom HaProxyMessageDecoder. (CVE-2022-41881)

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
    (XStream)).  Supported versions that are affected are 12.2.1.4.0. Those using Xstream to seralize 
    XML data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, 
    an attacker may supply content that causes the parser to crash by stack overflow. This effect may support a denial
    of service attack. (CVE-2022-40151)

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Security Framework 
    (jackson-databind)). Supported versions that are affected are 12.2.1.4.0. In FasterXML jackson-databind before 
    2.14.0-rc1, resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid 
    deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. Additional fix version in 
    2.13.4.1 and 2.12.17.1 (CVE-2022-42003)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported 
version number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e8adfc4");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36033");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.230404'}
];

vcf::oracle_webcenter_portal::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);