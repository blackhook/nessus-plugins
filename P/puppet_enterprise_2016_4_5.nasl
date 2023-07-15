#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129755);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id(
    "CVE-2017-2292",
    "CVE-2017-2293",
    "CVE-2017-2294",
    "CVE-2017-2295",
    "CVE-2017-2297"
  );
  script_bugtraq_id(98582);

  script_name(english:"Puppet Enterprise < 2016.4.5 / 2016.5.x / 2017.1.x Multiple Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet install on
the remote host is affected by multiple vulnerabilities :

  - A remote command execution vulnerability exists in the MCollective plugin
    due to unsafe YAML deserialization. An unauthenticated, remote attacker 
    can exploit this to bypass authentication and execute arbitrary commands. 
    (CVE-2017-2292, CVE-2017-2295)

  - An arbitrary package install vulnerability exists in the MCollective plugin
    due to unsafe default configuration. An unauthenticated, remote attacker 
    can exploit this to install or remove packages on all managed agents.
    (CVE-2017-2293)

  - An information disclosure vulnerability exists in the MCollective plugin
    due to unsafe storage of server private keys. An unauthenticated, remote attacker 
    can exploit this to view sensitive private keys.
    (CVE-2017-2294)
  
  - An authentication bypass vulnerability exists in labled RBAC access tokens. 
    An unauthenticated, attacker can exploit this, to bypass authentication 
    and execute arbitrary actions of users configured to use labeled RBAC
    access tokens. This issue has been fixed in Puppet Enterprise 2016.4.5 
    and 2017.2.1. This only affects users with labeled tokens, which is 
    not the default for tokens. (CVE-2017-2297)");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2017-2292");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2017-2293");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2017-2294");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2017-2295");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2017-2297");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2016.4.5 / 2017.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
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
  {"min_version" : "4.0.0", "fixed_version" : "4.10.1", "fixed_display" : "Puppet Enterprise (2016.4.5 / 2017.2.1)"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);