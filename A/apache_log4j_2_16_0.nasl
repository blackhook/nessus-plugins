#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156057);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2021-45046");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"2021-A-0598");
  script_xref(name:"IAVA", value:"2021-A-0597");
  script_xref(name:"IAVA", value:"2021-A-0596");
  script_xref(name:"IAVA", value:"0001-A-0650");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/22");

  script_name(english:"Apache Log4j 2.x < 2.16.0 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Log4j on the remote host is 2.x < 2.12.2 / 2.16.0. It is, therefore, affected by a remote 
code execution vulnerability. The fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain 
non-default configurations. This could allow attackers with control over Thread Context Map (MDC) input data 
when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, 
$${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using 
a JNDI Lookup pattern resulting in a remote code execution (RCE) attack.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-7rjr-3q55-vv33");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2021-45046");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Log4j version 2.3.1, 2.12.2, 2.16.0 or later, or apply the vendor mitigation.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45046");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_nix_installed.nbin", "apache_log4j_win_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Log4j';

var app_info = vcf::get_app_info(app:app);

if (report_paranoia != 2 && app_info['JndiLookup.class association'] == "Unknown")
  audit(AUDIT_OS_CONF_UNKNOWN, app, app_info.version);

if (app_info['JndiLookup.class association'] == "Not Found")
  audit(AUDIT_OS_CONF_NOT_VULN, app, app_info.version);

var constraints = [
  {'min_version':'2.0', 'fixed_version':'2.3.1'},
  {'min_version':'2.4', 'fixed_version':'2.12.2'},
  {'min_version':'2.13', 'fixed_version':'2.16.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);  

