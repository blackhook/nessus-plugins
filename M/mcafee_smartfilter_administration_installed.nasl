#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69915);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_xref(name:"IAVT", value:"0001-T-0859");

  script_name(english:"McAfee SmartFilter Administration Installed");
  script_summary(english:"Checks for McAfee SmartFilter");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has an administrative application installed.");
  script_set_attribute(attribute:"description", value:
"McAfee SmartFilter Administration, an administrative application for
McAfee SmartFilter, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://shop.mcafee.com/Products/SmartFilter.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:smartfilter_administration");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'McAfee SmartFilter';
# Connect to the appropriate share
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Secure Computing\SmartFilter Administration Console\installDir";
path = get_registry_value(handle:hklm, item:key);

key = "SOFTWARE\Secure Computing\SmartFilter Administration Console\version";
version = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
if (isnull(version))
{
  close_registry();
  exit(1, 'Failed to get the version of McAfee SmartFilter Administration Console from the registry.');
}
close_registry(close:FALSE);

# Make sure the application is actually installed
share = hotfix_path2share(path:path);
jar = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\support.jar", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  close_registry();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:jar,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  close_registry();
  audit(AUDIT_UNINST, app);
}
CloseFile(handle:fh);
NetUseDel();

set_kb_item(name:"SMB/McAfee SmartFilter Administration/Path", value:path);
set_kb_item(name:"SMB/McAfee SmartFilter Administration/Version", value:version);

register_install(
  vendor:"McAfee",
  product:"SmartFilter Administration",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:mcafee:smartfilter_administration");

report_installs(app_name:app, port:port);

