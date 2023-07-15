# (C) Tenable Network Security, Inc.

include("compat.inc");

if (description)
{
  script_id(119834);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-6978");
  script_bugtraq_id(106242);
  script_xref(name:"IAVB", value:"2018-B-0158");
  script_xref(name:"VMSA", value:"2018-0031");

  script_name(english:"VMware vRealize Operations Manager 6.6.x < 6.6.1.11286876 / 6.7.x <  6.7.0.11286837 / 7.x <  7.0.0.11287810 Local Privilege Escalation Vulnerability (VMSA-2018-0031)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"A cloud operations management application running on the remote web
server is affected by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Operations (vROps) Manager running on
the remote web server is 6.6.x prior to 6.6.1.11286876, 6.7.x prior
to 6.7.0.11286837, or 7.x prior to 7.0.0.11287810. It is, therefore,
affected by a privilege escalation vulnerability due to improper
permissions of support scripts. a local attacker with Admin account
shell access can exploit this to gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0031.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Operations Manager version
6.6.1.11286876 or 6.7.0.11286837 or 7.0.0.11287810 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6978");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");
  script_require_keys("installed_sw/vRealize Operations Manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "vRealize Operations Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  {"min_version":"6.6", "fixed_version":"6.6.1.11286876"},
  {"min_version":"6.7", "fixed_version":"6.7.0.11286837"},
  {"min_version":"7.0",   "fixed_version":"7.0.0.11287810"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

