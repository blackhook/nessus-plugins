#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156002);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2021-44228");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"2021-A-0596");
  script_xref(name:"IAVA", value:"2021-A-0597");
  script_xref(name:"IAVA", value:"2021-A-0598");
  script_xref(name:"IAVA", value:"0001-A-0650");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Apache Log4j < 2.15.0 Remote Code Execution (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Log4j on the remote host is 2.x < 2.15.0. It is, therefore, affected by a remote code execution
vulnerability in the JNDI parser due to improper log validation. An unauthenticated, remote attacker can exploit this
to bypass authentication and execute arbitrary commands. 

Log4j 1.x, which reached its End of Life prior to 2016, comes with JMSAppender which will perform a JNDI lookup if
enabled in Log4j's configuration file, hence customers should evaluate triggers in 1.x based on the risk that it is EOL
and whether JNDI lookups are enabled.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/logging-log4j2/pull/608");
  script_set_attribute(attribute:"see_also", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Log4j version 2.3.1 / 2.12.3 / 2.15.0 or later, or apply the vendor mitigation.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"windows");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_win_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app = 'Apache Log4j';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

if (report_paranoia != 2 && app_info['JndiLookup.class association'] == "Unknown")
  audit(AUDIT_OS_CONF_UNKNOWN, app, app_info.version);

if (app_info['JndiLookup.class association'] == 'Not Found')
  audit(AUDIT_OS_CONF_NOT_VULN, app, app_info.version);

var constraints = [
  { 'min_version' : '2.0', 'fixed_version' : '2.3.1' },
  { 'min_version' : '2.4', 'fixed_version' : '2.12.2' },
  { 'min_version' : '2.13', 'fixed_version' : '2.15.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
