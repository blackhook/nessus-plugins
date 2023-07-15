#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129759);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2018-6510", "CVE-2018-6511");

  script_name(english:"Puppet Enterprise 2017.x < 2017.3.6 Cross-site Scripting Vulnerability");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a code 
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet install 
running on the remote host is version 4.x prior to 2016.2.1, 5.3.x 
prior to 2017.3.7, or 5.5.x prior to 2018.1.1. It is, 
therefore, affected by a cross-site scripting (XSS) vulnerability 
due to improper validation of user-supplied input before returning it
 to users. An unauthenticated, remote attacker can exploit this, by 
 sending a specially crafted query to either the puppet enterprise 
 console or orchestrator, to execute arbitrary script code in a 
 user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2018-6513");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2017.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("puppet_enterprise_console_detect.nasl", "puppet_rest_detect.nasl");
  script_require_keys("puppet/rest_port", "installed_sw/puppet_enterprise_console");

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'Puppet REST API'; # we get both enterprise and open-source versions from the api...

# Make sure we detected a version 
port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');

# Make sure the Console service is running
get_kb_item_or_exit('installed_sw/puppet_enterprise_console');

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE, kb_ver: 'puppet/' + port + '/version');

# version info obtained from https://puppet.com/docs/pe/2018.1/component_versions_in_recent_pe_releases.html
constraints = [
  {"min_version" : "4.0.0", "fixed_version" : "4.10.12", "fixed_display" : "Puppet Enterprise (2016.4.5)"},
  {"min_version" : "5.3.0", "fixed_version" : "5.3.7" , "fixed_display" : "Puppet Enterprise (2017.3.7)"},
  {"min_version" : "5.5.0", "fixed_version" : "5.5.6" , "fixed_display" : "Puppet Enterprise (2018.1.1)" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);