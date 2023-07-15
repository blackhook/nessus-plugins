#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70069);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0635");

  script_name(english:"IBM WebSphere Service Registry and Repository Installed");
  script_summary(english:"Checks for IBM WebSphere Service Registry and Repository");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software life cycle management
application installed.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Service Registry and Repository, a software life cycle
management application, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78192efb");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_service_registry_and_repository");
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
include("global_settings.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

get_kb_item_or_exit("SMB/Registry/Enumerated");


# Find out where the Installation Manager is saving installation information
app = 'IBM WebSphere Service Registry and Repository';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\IBM\Installation Manager\appDataLocation";
appdatapath = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(appdatapath))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

# Look for the path in the installRegistry.xml file
share = hotfix_path2share(path:appdatapath);
xml = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\installRegistry.xml", string:appdatapath);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  close_registry();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:xml,
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

wsrrpath = NULL;
fsize = GetFileSize(handle:fh);
if (fsize)
{
  off = 0;
  pattern = "<profile id='IBM WebSphere Application Server";
  while (off < fsize)
  {
    data = ReadFile(handle:fh, length:10240, offset:off);
    if (strlen(data) == 0) break;

    if (pattern >< data)
    {
      chunk = strstr(data, pattern) - pattern;
      chunk = strstr(chunk, "<property name='installLocation'") - "<property name='installLocation' value='";
      wsrrpath = chunk - strstr(chunk, "'/>");
      break;
    }
    off += 10240;
  }
}
CloseFile(handle:fh);
if (isnull(wsrrpath) || wsrrpath !~ '^[A-Za-z]:.*') exit(1, 'Failed to get the path of WebSphere Service Registry and Repository.');
wsrrshare = hotfix_path2share(path:wsrrpath);

# If the app is on another share, connect to that one
if (wsrrshare != share)
{
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:wsrrshare);
  if (rc != 1)
  {
    close_registry();
    audit(AUDIT_SHARE_FAIL, wsrrshare);
  }
  if (rc != 1)
  {
    close_registry();
    audit(AUDIT_SHARE_FAIL, wsrrshare);
  }
}

wsrrpath = wsrrpath + "\WSRR";
properties = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\wsrrversion.properties", string:wsrrpath);;
fh = CreateFile(
  file:properties,
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
if (fsize)
{
  off = 0;
  while (off < fsize)
  {
    data = ReadFile(handle:fh, length:10240, offset:off);
    if (strlen(data) == 0) break;

    if ('version=' >< data)
    {
      chunk = strstr(data, 'version=') - 'version=';
      chunk = chunk - strstr(chunk, 'builddate');
      if ('_TRIAL' >< chunk) chunk = str_replace(string:chunk, find:'_TRIAL', replace:'');
      version = chomp(chunk);
      break;
    }
    off += 10240;
  }
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(version))
  audit(AUDIT_VER_FAIL, wsrrpath + "\wsrrversion.properties");

register_install(
  app_name:app,
  vendor : 'IBM',
  product : 'WebSphere Service Registry and Repository',
  path:wsrrpath,
  version:version,
  cpe:"cpe:/a:ibm:websphere_service_registry_and_repository");

report_installs(app_name:app, port:port);

