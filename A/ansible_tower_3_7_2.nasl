#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139386);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-14337");
  script_xref(name:"IAVB", value:"2020-B-0044");

  script_name(english:"Ansible Tower 3.x.x < 3.7.2 / 3.8.0 Data Exposure");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by a Data Exposure Flaw.");
  script_set_attribute(attribute:"description", value:
"The version of Ansible Tower running on the remote web server is
3.x.x prior to 3.7.2. It is, therefore, exposing data that can be mined
by reviewing information in error results. A remote, unauthenticated 
attacker can exploit this by reviewing this information to gain user names
and general site layout.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-14337");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2020-14337");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ansible Tower version 3.7.2, 3.8.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ansible:tower");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ansible_tower_installed.nbin", "ansible_tower_detect.nbin");
  script_require_ports("installed_sw/Ansible Tower", "installed_sw/Ansible Tower WebUI", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if(!isnull(get_kb_item('installed_sw/Ansible Tower')))
  app = vcf::get_app_info(app:'Ansible Tower');
else
{
  port = get_http_port(default:443);
  app = vcf::get_app_info(app:'Ansible Tower WebUI', webapp:TRUE, port:port);
}

constraints = 
[
  {'min_version' : '3.0.0', 'fixed_version' : '3.7.2'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);

