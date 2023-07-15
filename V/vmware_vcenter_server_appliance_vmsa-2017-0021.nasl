#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105514);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-4943");
  script_bugtraq_id(102242);

  script_name(english:"VMware vCenter Server Appliance 6.5 < 6.5 U1d Local Privilege Escalation (VMSA-2017-0021)");
  script_summary(english:"Checks the version of VMware vCenter Server Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server Appliance installed on the remote
host is 6.5 prior to 6.5 Update 1d (6.5 U1d). It is, therefore, affected by
a local privilege escalation vulnerability in the 'showlog' plugin.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0021.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server Appliance 6.5 Update 1d (6.5 U1d) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Server Appliance/Version", "Host/VMware vCenter Server Appliance/Build");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = 'VMware vCenter Server Appliance';
version = get_kb_item_or_exit("Host/"+appname+"/Version");
build   = get_kb_item_or_exit("Host/"+appname+"/Build");
port    = 0;
fixversion_str = NULL;

if (version !~ "^6\.5($|[^0-9])")
  audit(AUDIT_NOT_INST, appname + " 6.5.x");

if (version =~ "^6\.5($|[^0-9])")
{
  fixed_main_ver = "6.5.0";
  fixed_build    = 7312210;

  if (int(build) < fixed_build)
    fixversion_str = fixed_main_ver + ' build-'+fixed_build;
}

if (isnull(fixversion_str))
  audit(AUDIT_INST_VER_NOT_VULN, appname, version, build);

report = report_items_str(
  report_items:make_array(
    "Installed version", version + ' build-' + build,
    "Fixed version", fixed_main_ver + ' build-' + fixed_build
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
