#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129754);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-5714", "CVE-2016-5715");
  script_bugtraq_id(93846);

  script_name(english:"Puppet Enterprise < 2016.4.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application running on the remote host is version 
prior to 2016.2.1. It is, therefore, affected by the following 
vulnerabilities :

  - An information disclosure vulnerability exists in the environment
    catalog component. An unauthenticated remote attacker can exploit 
    this issue to retrieve access to the enviroment catalogs which 
    may reveal sensitive information about infrastructure of application
    orchestration users.(CVE-2016-5714)

  - An url redirection vulnerability exists in the next page transition. 
    An unauthenticated remote attacker can exploit
    this issue to create believable phishing attacks.(CVE-2016-5715)");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2016-5714");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2016-5715");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2016.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5714");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
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

# version info obtained from https://puppet.com/docs/pe/2016.2/overview_version_table.html
constraints = [
  {"min_version" : "3.0.0", "fixed_version" : "4.7.0", "fixed_display" : "Puppet Enterprise (2016.4.0)"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);