#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68927);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_name(english:"Blue Coat Authentication and Authorization Agent (BCAAA) Installed");
  script_summary(english:"Checks for BCAAA");

  script_set_attribute(attribute:"synopsis", value:"An authentication application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Blue Coat Authentication and Authorization Agent, an authentication
agent, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://kb.bluecoat.com/index?page=content&id=FAQ422&actp=RSS");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bluecoat:proxysg");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i < l; i++)
    res += str[i] + null;

  return res;
}

app = 'Blue Coat Authentication and Authorization Agent';
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SYSTEM\CurrentControlSet\services\BCAAA\ImagePath";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);
exe = str_replace(string:path, find:'"', replace:'');
path = exe - "\bcaaa.exe";
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:exe, replace:"\1");

share = hotfix_path2share(path:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, app);
}

version = NULL;
fsize = GetFileSize(handle:fh);
off = fsize - 10240;
pat = 'FileVersion';
while (off > 0)
{
  data = ReadFile(handle:fh, length:10240, offset:off);
  if (strlen(data) == 0) break;

  if (mk_unicode(str:pat) >< data)
  {
    chunk = strstr(data, mk_unicode(str:pat)) - mk_unicode(str:pat);
    chunk = chunk - strstr(chunk, mk_unicode(str:'InternalName'));
    chunk = chomp(chunk);

    # Remove unicode separators
    for (i=4; i < strlen(chunk); i+= 2)
      version += chunk[i];
    break;
  }
  off -= 10240;
}
CloseFile(handle:fh);
NetUseDel();
ver = split(version, sep:'.', keep:FALSE);
if (max_index(ver) > 5)
  version = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3] + '.' + ver[4];

set_kb_item(name:'SMB/BCAAA/Path', value:path);
set_kb_item(name:'SMB/BCAAA/Version', value:version);

register_install(
  vendor:"Blue Coat",
  product:"ProxySG",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:bluecoat:proxysg");

report_installs(app_name:app, port:port);

