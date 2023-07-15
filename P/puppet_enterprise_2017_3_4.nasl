#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129758);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2017-10690", "CVE-2018-6508");
  script_bugtraq_id(103020);

  script_name(english:"Puppet Enterprise < 2017.3.4 Code Execution Vulnerability");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a code 
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet install 
running on the remote host is version 5.5.x prior to 2017.3.4. It is, 
therefore, affected by multiple vulnerabilities: 

  - a remote code execution vulnerability due to incorrect 
    validation of strings in the facter_task or puppet_conf tasks. An 
    unauthenticated remote attacker can exploit this issue to send a 
    specially crafted string into the affected tasks to remotely execute
    code. (CVE-2018-6508)

  - an information disclosure vulnerability exists. An 
    unauthenticated remote attacker can exploit this issue to retrieve a 
    facts from an environment it was not classified to retrieve from. 
    (CVE-2017-10690)");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2017-10690");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2018-6508");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2016.4.12 / 2017.3.7 / 2018.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/07");
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
  {"min_version" : "5.3.0", "fixed_version" : "5.3.4" , "fixed_display" : "Puppet Enterprise (2017.3.4)"},
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);