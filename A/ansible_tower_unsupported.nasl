#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112213);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"0001-A-0514");

  script_name(english:"Ansible Tower Unsupported Version");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host running an unsupported version.");
  script_set_attribute(attribute:"description", value:
"The version of Ansible Tower running on the remote server has
reached the end of support, and will no longer receive security updates
from the vendor. It could therefore be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/support/policy/updates/ansible-tower");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a currently supported version of Ansible Tower.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ansible:tower");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ansible_tower_installed.nbin", "ansible_tower_detect.nbin");
  script_require_ports("installed_sw/Ansible Tower", "installed_sw/Ansible Tower WebUI", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if(!isnull(get_kb_item("installed_sw/Ansible Tower")))
  app = vcf::get_app_info(app:"Ansible Tower");
else
{
  port = get_http_port(default:443);
  app = vcf::get_app_info(app:"Ansible Tower WebUI", webapp:TRUE, port:port);
}

constraints = 
[
  {"fixed_version" : "3.3.0", "fixed_display":"3.3.x / 3.4.x or later."}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
