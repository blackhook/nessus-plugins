#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55818);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"IBM Domino Installed");
  script_summary(english:"Checks version of IBM Domino (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:"The remote host has IBM Domino installed.");
  script_set_attribute(attribute:"description", value:
"IBM Domino (formerly IBM Lotus Domino), an enterprise application for
collaborative messaging, scheduling, directory services, and web
services, is installed on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20180209113148/http://www-03.ibm.com:80/software/products/en/ibmdomino");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = 'IBM Domino';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_array();

# Get filename of main executable (e.g. nserver.exe)
key  = "SOFTWARE\Lotus\Domino\Name";
file = get_registry_value(handle:hklm, item:key);

# Get path
key  = "SOFTWARE\Lotus\Domino\Path";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

if (isnull(file))
{
  close_registry();
  exit(1, "Could not find name of IBM Domino's main executable.");
}

close_registry(close:FALSE);

exe = hotfix_append_path(path:path, value:file);
ver = hotfix_get_fversion(path:exe);
hotfix_handle_error(error_code:ver['error'],
                    file:exe,
                    appname:app,
                    exit_on_fail:TRUE);

version = join(ver['value'], sep:'.');

# Get FP and HF information
notes_ini = hotfix_append_path(path:path, value:"notes.ini");
data = hotfix_get_file_contents(notes_ini);
hotfix_handle_error(error_code:data['error'], appname:app, file:notes_ini, exit_on_fail:TRUE);
data = data['data'];

matches = pregmatch(string:data, pattern:"CFP_LP_CURRENT=Release ([0-9.]+)(FP([0-9]))?( HF([0-9]+))?");

base_version = UNKNOWN_VER;
feature_pack = 0;
hot_fix = 0;
if(!empty_or_null(matches))
{
  base_version = matches[1];
  if (!empty_or_null(matches[3]))
    feature_pack = matches[3];
  if (!empty_or_null(matches[5]))
    hot_fix = matches[5];
}
extra = make_array();
extra['Base Version'] = base_version;
extra['Feature Pack'] = feature_pack;
extra['Hot Fix'] = hot_fix;

# Report our findings.
set_kb_item(name:"SMB/Domino/Installed", value:TRUE);
set_kb_item(name:"SMB/Domino/Path", value:path);
set_kb_item(name:"SMB/Domino/Version", value:version);

# Get 'jvm.dll' version
dll = hotfix_append_path(path:path, value:"jvm\bin\classic\jvm.dll");
ver = hotfix_get_fversion(path:dll);
hotfix_handle_error(error_code:ver['error'],
                    file:dll,
                    appname:app,
                    exit_on_fail:FALSE);

hotfix_check_fversion_end();

if (ver)
{
  ver_jvm = join(ver['value'], sep:'.');
  set_kb_item(name:"SMB/Domino/Java_Version", value:ver_jvm);
  extra['Java Version'] = ver_jvm;
}

register_install(
  app_name:app,
  vendor : 'IBM',
  product : 'Lotus Domino',
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:ibm:lotus_domino");

report_installs(app_name:app, port:port);
