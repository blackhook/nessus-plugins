#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156327);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/04");

  script_cve_id("CVE-2021-44832");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"0001-A-0650");

  script_name(english:"Apache Log4j 2.0 < 2.3.2 / 2.4 < 2.12.4 / 2.13 < 2.17.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Log4j on the remote host is 2.0 < 2.3.2, 2.4 < 2.12.4, or 2.13 < 2.17.1. It is, therefore,
affected by a remote code execution vulnerability. Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security
fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack where an attacker with permission
to modify the logging configuration file can construct a malicious configuration using a JDBC Appender with a data
source referencing a JNDI URI which can execute remote code. This issue is fixed by limiting JNDI data source names to
the java protocol in Log4j2 versions 2.17.1, 2.12.4, and 2.3.2. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Log4j version 2.17.1, 2.12.4, or 2.3.2 or later, or apply the vendor mitigation.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_nix_installed.nbin", "apache_log4j_win_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Log4j';

var app_info = vcf::get_app_info(app:app);

if (app_info['JdbcAppender.class association'] == "Not Found")
  audit(AUDIT_OS_CONF_NOT_VULN, app, app_info.version);

var constraints = [
  {'min_version':'2.0', 'fixed_version':'2.3.2'},
  {'min_version':'2.4', 'fixed_version':'2.12.4'},
  {'min_version':'2.13', 'fixed_version':'2.17.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

