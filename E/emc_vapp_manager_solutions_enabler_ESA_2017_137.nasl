#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104389);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2017-14375");

  script_name(english:"EMC Solutions Enabler Virtual Appliance < 8.4.0.15 Authentication Bypass Vulnerability");
  script_summary(english:"Checks the version of EMC vApp Manager for Solutions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote virtual appliance is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC Solutions Enabler Virtual Appliance running on the
remote host is prior to 8.4.0.15. It is, therefore, affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Oct/70");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Solutions Enabler Virtual Appliance version 8.4.0.15
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:solutions_enabler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_vapp_manager_detect.nbin");
  script_require_keys("Host/EMC/Solutions Enabler Virtual Appliance", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("http_func.inc");

# A hotfix can be applied to 8.3.0.33
if (report_paranoia < 2) audit(AUDIT_PARANOID);

appliance = "Solutions Enabler Virtual Appliance";
port = get_http_port(default:5480, embedded:TRUE);

app_info = vcf::get_app_info(app:appliance, port:port, kb_ver:"Host/EMC/"+appliance+"/Version", webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"fixed_version" : "8.4.0.15"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
