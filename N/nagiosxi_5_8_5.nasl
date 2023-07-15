#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153612);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2021-33177",
    "CVE-2021-33179",
    "CVE-2021-36363",
    "CVE-2021-36364",
    "CVE-2021-36365",
    "CVE-2021-36366",
    "CVE-2021-37343",
    "CVE-2021-37345",
    "CVE-2021-37347",
    "CVE-2021-37348",
    "CVE-2021-37349",
    "CVE-2021-37350",
    "CVE-2021-37351",
    "CVE-2021-37352"
  );
  script_xref(name:"IAVB", value:"2021-B-0053");

  script_name(english:"Nagios XI < 5.8.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Nagios XI, the remote host is affected by multiple vulnerabilities, including
the following:

  - A path traversal vulnerability exists in Nagios XI below version 5.8.5 AutoDiscovery component and could lead to post 
    authenticated RCE under security context of the user running Nagios. (CVE-2021-37343)

  - Nagios XI before version 5.8.5 is vulnerable to local privilege escalation because xi-sys.cfg is being imported from 
    the var directory for some scripts with elevated permissions. (CVE-2021-37345)

  - Nagios XI before version 5.8.5 is vulnerable to SQL injection vulnerability in Bulk Modifications Tool due to improper 
    input sanitisation. (CVE-2021-37350)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/downloads/nagios-xi/change-log/");
  script_set_attribute(attribute:"see_also", value:"https://www.nagios.com/products/security/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nagios XI 5.8.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37350");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios XI Autodiscovery Webshell Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl");
  script_require_keys("installed_sw/nagios_xi");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http_func.inc');
include('vcf_extras.inc');

var app = 'nagios_xi';

# Get the ports that web servers have been found on.
var port = get_http_port(default:80, embedded:TRUE);

var app_info = vcf::nagiosxi::get_app_info(port:port);

var constraints = [
    {'fixed_version': '5.8.5'}
];

vcf::nagiosxi::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, default_fix:'5.8.5');
