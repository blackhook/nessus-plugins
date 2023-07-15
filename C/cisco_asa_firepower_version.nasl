#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
 script_id(131952);
 script_version("1.6");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0547");

 script_name(english:"Cisco ASA Firepower Version");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the ASA FXOS or FTD version number of the remote Cisco
device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the Cisco Adaptive Security Appliance (ASA) operating system with the Firepower eXtensible
Operating System (FXOS) or Firepower Threat Defense (FTD). 

It is possible to read the ASA FXOS or FTD version number by connecting to the device via SSH.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
 script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CISCO");

 script_dependencies("ssh_get_info.nasl");
 script_require_ports("Host/Cisco/show_ver");
 exit(0); 
}

include('global_settings.inc');
include('audit.inc');
include('install_func.inc');
include('spad_log_func.inc');

##
# Register and report the Firepower install
# @param app_name the app name for FXOS or FTD
# @param version The version, possibly empty
# @param cpe the CPE for the app
# @param model The model, possibly empty
# @param vdb_ver The VDB version, optional, for FTD only
##
function register_and_report_firepower(app_name, version, cpe, model, vdb_ver)
{
  local_var extra = make_array();

  if (!empty_or_null(model))
    extra['Model'] = model;
  if (!empty_or_null(vdb_ver))
    extra['VDB Version'] = vdb_ver;

  register_install(
      app_name : app_name,
      vendor : 'Cisco',
      product : 'Firepower Threat Defense',
      path: '/',
      version: version,
      extra : extra,
      cpe : cpe
  );
  report_installs(app_name:app);
}

s = get_kb_item_or_exit('Host/Cisco/show_ver');

if (!egrep(string: s, pattern: "(ASA|Adaptive Security Appliance)"))
  audit(AUDIT_HOST_NOT, 'Cisco ASA');

is_fxos = FALSE;
if(egrep(string: s, pattern: "Firepower Extensible Operating System"))
{
  is_fxos = TRUE;
  app = 'FXOS';
  cpe = 'cpe:/o:cisco:fxos';
  # ssh_get_info.nasl parses and sets an ASA model key, however it comes from "Hardware" and on ASA/FXOS we see
  # "Model Id:" is more accurate
  m = pregmatch(string: s, pattern: "\nModel Id:\s*ASA\s*([^,]+?)?(,|\r\n|$)");
  if (isnull(m))
    model = get_kb_item('Host/Cisco/ASA/model');
  else
    model = m[1];
  v = pregmatch(string: s, pattern: "Firepower Extensible Operating System Version (\d+\.\d+(\(([\d.])+\))?)");
  if (isnull(v))
    ver = '';
  else
    ver = v[1];
  register_and_report_firepower(app_name:app, version:ver, cpe:cpe, model:model);
}

is_ftd = FALSE;
if (egrep(string: s, pattern: "Threat Defense"))
{
  is_ftd = TRUE;
  app = 'Cisco Firepower Threat Defense';
  cpe = 'cpe:/a:cisco:firepower_threat_defense';
  # ssh_get_info.nasl should set model
  model = get_kb_item('Host/Cisco/ASA/model');
  # ASA/FTD also has VDB info
  vdb = pregmatch(string: s, pattern:"VDB version\s+: (\d+)");
  if (!isnull(vdb))
    vdb_ver = vdb[1];
  # -------------[ example-sfr.example.com ]--------------
  # Model                     : Cisco ASA5508-X Threat Defense (75) Version 6.1.0 (Build 226)
  # UUID                      : 43235986-2363-11e6-b278-aff0a43948fe
  # Rules update version      : 2016-03-28-001-vrt
  # VDB version               : 270
  v = pregmatch(string: s, pattern: "Version\s+([0-9.]+)( \(Build (\d+)\))?");
  if (isnull(v))
    ver = '';
  else
  {
    ver = v[1];
    if (!empty_or_null(v[3]))
      ver += '.' + v[3];
  }
  register_and_report_firepower(app_name:app, version:ver, cpe:cpe, model:model, vdb_ver:vdb_ver);
}

if (!is_ftd && !is_fxos)
 audit(AUDIT_HOST_NOT, 'Cisco FTD or FXOS');
