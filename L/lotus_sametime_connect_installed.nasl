#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70071);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"IBM Lotus Sametime Connect Client Installed");
  script_summary(english:"Checks for IBM Lotus Sametime Connect Client");

  script_set_attribute(attribute:"synopsis", value:"A communications client is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"IBM Lotus Sametime Connect Client, a communications client
application, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20131030171143/http://www-03.ibm.com:80/software/products/us/en/ibmsame");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_sametime");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'IBM Lotus Sametime Client';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\IBM\Sametime Connect\BasePath";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

fp_build_path = hotfix_append_path(path:path, value:"fp_build_identification.properties");
build_path = hotfix_append_path(path:path, value:"build_identification.properties");

# Try to get fixpack info.
if (hotfix_file_exists(path:fp_build_path))
{
  fp_build_properties = smb_get_properties(path:fp_build_path, appname:appname);

  version = fp_build_properties['fixpack.release'];
  fixpackdate = fp_build_properties['fixpack.date'];

  # Check for IFR info.
  ifr = eregmatch(string:fp_build_properties['fixpack.tag'], pattern:"(IFR \d+)");
  if (ifr) version += ' ' + ifr[1];
}
else
{
  build_properties = smb_get_properties(path:build_path, appname:appname);

  version = build_properties['build.release'];
}

set_kb_item(name:'SMB/'+appname+'/Path', value:path);
set_kb_item(name:'SMB/'+appname+'/Version', value:version);

extra = make_array();
if (fixpackdate)
{
  set_kb_item(name:'SMB/'+appname+'/fixpackdate', value:fixpackdate);
  extra["Fix Pack Date"] = fixpackdate;
}

register_install(
  app_name:appname,
  vendor : 'IBM',
  product : 'Lotus Sametime',
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:ibm:lotus_sametime");

report_installs(app_name:appname, port:port);

