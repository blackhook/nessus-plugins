#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129752);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2016-2786", "CVE-2016-2787");
  script_bugtraq_id(91163, 96359);

  script_name(english:"Puppet Enterprise 2015.x < 2015.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application running on the remote host is version 2015.x 
prior to 2015.3.3. It is, therefore, affected by the following 
vulnerabilities :

  - A invalid validation of the server certificate by the pxp-agent. 
    An unauthenticated, remote attacker can impersonate a broker and 
    issue commands to the agent. This requires a secondary attack 
    which forces the agent to connect to the malicious broker.
    (CVE-2016-2786)

  - A denial of service vulnerability exists due to the incorrect
    validation of the broker node certificates.  An unauthenticated, 
    remote attacker can prevent the puppet communications protocol 
    from triggering runs.  (CVE-2016-2787)");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/cve-2016-2786");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/cve-2016-2787");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2015.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/14");
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
  {"min_version" : "4.3.0", "fixed_version" : "4.3.2", "fixed_display" : "Puppet Enterprise (2015.3.3)"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
