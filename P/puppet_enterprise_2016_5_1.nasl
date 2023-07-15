#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129756);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2016-9686");
  script_bugtraq_id(96319);

  script_name(english:"Puppet Enterprise 2015.x < 2016.4.0 Denial of Service Vulnerability");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet install 
running on the remote host is version 5.5.x prior to 2017.2.2. It is, 
therefore, affected by a denial of service (DoS) vulnerability which 
exists in the puppet communications protocol broker due to incorrect 
validation of message header sizes. An unauthenticated remote 
attacker can exploit this issue to creash the pcp broker and prevent 
commands from being seint to agents.");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2016-9686");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2016.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
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
  {"min_version" : "4.0.0", "fixed_version" : "4.7.1", "fixed_display" : "Puppet Enterprise (2016.4.3)"},
  {"min_version" : "4.8.0", "fixed_version" : "4.8.2", "fixed_display" : "Puppet Enterprise (2016.5.2)"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);