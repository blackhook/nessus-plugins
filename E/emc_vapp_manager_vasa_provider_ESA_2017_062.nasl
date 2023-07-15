#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102036);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2017-4997");
  script_bugtraq_id(99169);
  script_xref(name:"ZDI", value:"ZDI-17-491");

  script_name(english:"EMC VMAX VASA Provider Virtual Appliance < 8.4.0 File Upload RCE");
  script_summary(english:"Checks the version of EMC vApp Manager for VMAX VASA Provider.");

  script_set_attribute(attribute:"synopsis", value:
"The remote virtual appliance is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC VMAX VASA Provider Virtual Appliance running on
the remote host is prior to 8.4.0. It is, therefore, affected by a
remote code execution vulnerability in the UploadConfigurator servlet
due to a failure to restrict file uploads to arbitrary directories. An
unauthenticated, remote attacker can exploit this issue to upload
files containing arbitrary code and then execute them with root
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2017/Jun/att-55/ESA-2017-062.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-491/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC VMAX VASA Provider Virtual Appliance version 8.4.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:emc:vasa_provider_virtual_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_vapp_manager_detect.nbin");
  script_require_keys("Host/EMC/VMAX VASA Provider Virtual Appliance");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http_func.inc");

appliance = "VMAX VASA Provider Virtual Appliance";
version   = get_kb_item_or_exit("Host/EMC/"+appliance+"/Version");

port = get_http_port(default:5480, embedded:TRUE); 
vapp = "EMC vApp Manager";

# Exit if vapp is not detected on this port
get_single_install(app_name:vapp, port:port);

fix    = '8.4.0';

ret = ver_compare(ver:version, fix:fix, strict:FALSE);
if (ret >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, vapp + " for " +  appliance, port, version);

report_items = make_array(
  "Appliance version", version,
  "Fixed version", fix
);

ordered_fields = make_list("Appliance version", "Fixed version");

report = report_items_str(report_items:report_items, ordered_fields:ordered_fields);

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
