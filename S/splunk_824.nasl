#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158383);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_xref(name:"IAVA", value:"2022-A-0093");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Splunk Enterprise 8.1.x < 8.1.7.2 / 8.2.x < 8.2.3.3 Log4j");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk running on the remote web server is Splunk
Enterprise 8.1.x prior to 8.1.7.2 or 8.2.x prior to 8.2.3.3. It may, therefore, be affected by the following
vulnerabilities related to the use of Log4j, as follows:

  - Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI
    features used in configuration, log messages, and parameters do not protect against attacker controlled
    LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters
    can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From
    log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3,
    and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to
    log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.
    (CVE-2021-44228)

  - It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain
    non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input
    data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for
    example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input
    data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some
    environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix
    this issue by removing support for message lookup patterns and disabling JNDI functionality by default.
    (CVE-2021-45046)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.splunk.com/en_us/blog/bulletins/splunk-security-advisory-for-apache-log4j-cve-2021-44228.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56494a5c");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 8.1.7.2, 8.2.3.2, 8.2.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44228");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Splunk");
  script_require_ports("Services/www", 8089, 8000);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var os = get_kb_item('Host/OS');
if ('windows' >< tolower(os))
  audit(AUDIT_HOST_NOT, 'vulnerable as it is running Windows.');

var app = 'Splunk';
var port = get_http_port(default:8000, embedded:TRUE);

var app_info = vcf::get_app_info(app:app, port:port);

# Only 8.1 and 8.2 can be vulnerable - audit out definitively if it's not this version before checking for paranoia
if (app_info['version'] !~ "^8\.[12]([^0-9]|$)")
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

if (app_info['License'] == 'Enterprise')
{
  var constraints = [
    { 'min_version' : '8.1', 'fixed_version' : '8.1.7.2' },
    { 'min_version' : '8.2', 'fixed_version' : '8.2.3.3', 'fixed_display' : '8.2.3.3 / 8.2.4' }
  ];
}
# Other license or no license, report not vulnerable
else {
  audit(AUDIT_LISTEN_NOT_VULN, app, port);
}

# Not checking for the vulnerable DFS configuration, so require paranoia
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info['version'], port);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

