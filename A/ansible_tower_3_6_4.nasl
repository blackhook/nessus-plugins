#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135182);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-10697");
  script_xref(name:"IAVB", value:"2020-B-0016-S");

  script_name(english:"Ansible Tower 3.4.x < 3.4.6 / 3.5.x < 3.5.6 / 3.6.x < 3.6.4 Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by a Denial of Service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ansible Tower running on the remote web server is
3.4.x prior to 3.4.6, or 3.5.x prior to 3.5.6, or 3.6.x prior to
3.6.4. It is, therefore, affected by a Denial of Service vulnerability
when running Openshift that can reduce memcached and Tower performance.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-10697");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2020-10697");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ansible Tower version 3.4.6 / 3.5.6 / 3.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

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

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
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
  {'min_version' : '3.4.0', 'fixed_version' : '3.4.6'},
  {'min_version' : '3.5.0', 'fixed_version' : '3.5.6'},
  {'min_version' : '3.6.0', 'fixed_version' : '3.6.4'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_NOTE, strict:FALSE);
