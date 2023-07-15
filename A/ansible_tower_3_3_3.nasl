#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127125);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-16879");
  script_bugtraq_id(106310);

  script_name(english:"Ansible Tower 3.x < 3.3.3 Unauthorized Access vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by
a Unauthorized Access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ansible Tower running on the remote web server is 3.x
prior to 3.3.3. It is, therefore, affected by an unauthorized access 
vulnerability due to a RabbitMQ misconfiguration.  The configuration
does not set a secure channel for messaging celery workers, resulting
in a leak of sensitive data and the deletion of projects & files.");
  # https://docs.ansible.com/ansible-tower/3.3.3/html/release-notes/relnotes.html#ansible-tower-version-3-3-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6565aa42");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ansible Tower version 3.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16879");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ansible:tower");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {"min_version" : "3.0.0", "fixed_version" : "3.3.3"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
