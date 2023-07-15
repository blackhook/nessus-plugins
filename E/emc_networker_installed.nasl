#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62945);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_xref(name:"IAVT", value:"0001-T-0593");

  script_name(english:"EMC NetWorker Installed");
  script_summary(english:"Checks the registry / filesystem for EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"A backup and recovery application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"EMC NetWorker (formerly Legato NetWorker), a suite of enterprise level
data protection software, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.emc.com/data-protection/networker.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:legato_networker");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services_params.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('install_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('spad_log_func.inc');

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Legato\Networker";
item = get_values_from_key(handle:handle, key:key, entries:make_list('Path'));
if(empty_or_null(item))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'EMC NetWorker');
}
path = item['Path'];
build = 0;

key = "SOFTWARE\Legato\Networker\Release";
regversion = get_registry_value(handle:handle, item:key);
if (!isnull(regversion))
{
  build = int(ereg_replace(string:regversion, pattern:'^.*Build\\.([0-9]+)$', replace:"\1"));
  regversion = ereg_replace(string:regversion, pattern:'^([0-9\\.]+)\\.Build.*$', replace:"\1");
}

# Networker Management Console (NMC) (a.k.a GST)
key = "SOFTWARE\Legato\GST\Release";
var nmc_release = get_registry_value(handle:handle, item:key);
if (!empty_or_null(nmc_release))
{
  key = strcat("SOFTWARE\Legato\GST\", nmc_release, "\InstallPath"); 
  var nmc_path = get_registry_value(handle:handle, item:key);
}

key = "SYSTEM\CurrentControlSet\services\nsrd";
reg_serv = get_registry_subkeys(handle:handle, key:key);
is_server = !isnull(reg_serv);
RegCloseKey(handle:handle);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'EMC NetWorker');
}
close_registry(close:FALSE);

fileName        = hotfix_append_path(path:path, value:"bin\winworkr.exe");
fileName_nmm    = hotfix_append_path(path:path, value:"bin\EMC.NetWorker.dll");
fileName_nmmedi = hotfix_append_path(path:path, value:"bin\nwmedisan.dll");

item = hotfix_get_fversion(path:fileName);
if (item['error'] != HCF_OK)
{
  # If we couldn't get the version from the file, it may be a permissions issue
  # See if we got it from the registry.
  if (isnull(regversion))
     hotfix_handle_error(error_code:item['error'], appname:'EMC NetWorker', file:fileName, exit_on_fail:TRUE);
  else version = regversion;
}
else version = join(item['value'], sep:".");

extra = make_array();

# Check for the Management Console
extra['Management Console Installed'] = 'false';

if (!empty_or_null(nmc_path))
{
  var nmc_exe = hotfix_append_path(path:nmc_path, value:"GST\bin\gstd.exe");
  item = hotfix_get_fversion(path:nmc_exe);
  if (item['error'] != HCF_OK)
  {
    var error = hotfix_handle_error(error_code:item['error'], file:nmc_exe);
    spad_log(message:error);
  }
  else
  {
    extra['Management Console Installed'] = 'true';
    extra['Management Console Version']   = item.version;
  }
}

extra['Server'] = is_server;
###################################################
# Gets Module for Microsoft Apps Version
item  = hotfix_get_fversion(path:fileName_nmm);
if (item['error'] == HCF_OK)
{
  version_nmm = join(item['value'], sep:".");
  extra["Module for Microsoft Applications Version"] = version_nmm;
}
###################################################
# Gets Module for MEDITECH
item = hotfix_get_fversion(path:fileName_nmmedi);
if (item['error'] == HCF_OK)
{
  version_nmmedi = join(item['value'], sep:".");
  extra["Module for MEDITECH Version"] = version_nmmedi;
}

# If we got a build number from the registry
if (build > 0)
  extra["Build"] = build;

hotfix_check_fversion_end();

# Don't register install with an empty array
if(max_index(keys(extra)) == 0) extra = NULL;

register_install(
  vendor:"EMC",
  product:"Networker",
  app_name:'EMC NetWorker',
  path:path,
  extra:extra,
  version:version,
  cpe:"cpe:/a:emc:networker"
);

report_installs();
