#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62688);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Adobe Media Encoder Installed");
  script_summary(english:"Checks registry/fs for AME");

  script_set_attribute(attribute:"synopsis", value:"A media encoder is installed on the remote host.");
  script_set_attribute(attribute:"description", value:"Adobe Media Encoder is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/media-encoder.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder_cs4");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

app = 'Adobe Media Encoder';
get_kb_item_or_exit('SMB/Registry/Enumerated');
registry_init();
hkcr = registry_hive_connect(hive:HKEY_CLASS_ROOT, exit_on_fail:TRUE);

# 32-bit
name = "AMECS6ProjectFile\shell\Open\command\";
cmd = get_registry_value(handle:hkcr, item:name);
if (!isnull(cmd))
{
  match = pregmatch(string:cmd, pattern:'^"(\\w:.+\\.exe)"');
  if (!isnull(match))
    exe = match[1];
}

# 64-bit
if (isnull(exe))
{
  name = "AME1ProjectFile_64\shell\Open\command\";
  cmd = get_registry_value(handle:hkcr, item:name);
  if (!isnull(cmd))
  {
    match = pregmatch(string:cmd, pattern:'^"(\\w:.+\\.exe)"');
    if (!isnull(match))
      exe = match[1];
  }
}

RegCloseKey(handle:hkcr);

if (isnull(exe))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);
ver =  hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_OK)
  version = join(ver['value'], sep:'.');
else
  audit(AUDIT_UNINST, app);

path_parts = split(exe, sep:"\", keep:TRUE);
path = '';
for (i = 0; i < max_index(path_parts) - 1; i++)
  path += path_parts[i];

set_kb_item(name:'SMB/Adobe_Media_Encoder/'+version+'/Path', value:path);
set_kb_item(name:'SMB/Adobe_Media_Encoder/'+version+'/ExePath', value:exe);
set_kb_item(name:'SMB/Adobe_Media_Encoder/installed', value:TRUE);

register_install(
  app_name:app,
  vendor : 'Adobe',
  product : 'Media Encoder CS4',
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:media_encoder_cs4");

port = kb_smb_transport();

report_installs(app_name:app, port:port);

