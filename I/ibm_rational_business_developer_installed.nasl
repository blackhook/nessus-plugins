#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66306);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"IBM Rational Business Developer Installed");
  script_summary(english:"Checks for IBM Rational Business Developer");

  script_set_attribute(attribute:"synopsis", value:"A development environment is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"IBM Rational Business Developer, an Eclipse-based programming
workbench, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20131026024806/http://www-03.ibm.com/software/products/us/en/busdeveloper/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_business_developer");
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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

app = 'IBM Rational Business Developer';
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (display_name =~ 'IBM Software Delivery Platform')
  {
    key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
    key = str_replace(string:key, find:'/', replace:'\\');
    key += 'UninstallString';
    uninstall = get_registry_value(handle:hklm, item:key);
    break;
  }
}
if (isnull(uninstall))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

path = strstr(uninstall, '-input ') - '-input ';
path = str_replace(string:path, find:'"', replace:'');
path = path - 'uninstall\\uninstall.xml';

share = hotfix_path2share(path:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

reportpath = path;
path = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1rbd\properties\version", string:path);
version = NULL;
file = NULL;
# Loop over the files to look for the version swtag file
retx = FindFirstFile(pattern:path+'\\IBM_Rational_Business_Developer*');
while (!isnull(retx[1]))
{
  if ((retx[1] != '.' && retx[1] != '..') && retx[1] =~ 'IBM_Rational_Business_Developer.[0-9\\.]+')
  {
    file = path + '\\' + retx[1];

    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (isnull(fh))
      continue;
    contents = ReadFile(handle:fh, offset:0, length:1024);
    if (contents)
    {
      version = strstr(contents, '<ProductVersion>') - '<ProductVersion>';
      version = version - strstr(contents, '</ProductVersion>');
      break;
    }
    CloseFile(handle:fh);
  }
  retx = FindNextFile(handle:retx);
}
NetUseDel();

if (isnull(file)) audit(AUDIT_NOT_INST, app);

if (isnull(version) || version !~ '^[0-9\\.]+$')
  audit(AUDIT_VER_FAIL, ((share - '$') + ':') + file);

set_kb_item(name:'SMB/'+app+'/Path', value:reportpath);
set_kb_item(name:'SMB/'+app+'/Version', value:version);

register_install(
  app_name:app,
  path:reportpath,
  vendor:"IBM",
  product:"Rational Business Developer",
  version:version,
  cpe:"cpe:/a:ibm:rational_business_developer");

report_installs(app_name:app, port:port);

