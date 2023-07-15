#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57364);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_name(english:"PuTTY Detection");
  script_summary(english:"Checks for the presence of PuTTY");

  script_set_attribute(attribute:"synopsis", value:"A Telnet / SSH client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY, which is a suite of
tools for remote console access and file transfer.");
  script_set_attribute(attribute:"see_also", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = 'PuTTY';
version = UNKNOWN_VER;
path = NULL;

key = hotfix_displayname_in_uninstall_key(pattern:"^PuTTY");

if (key == FALSE)
  audit(AUDIT_NOT_INST, app);

key = key - "SMB/Registry/HKLM/";
key = key - "/DisplayName";
key = str_replace(string:key, find:"/", replace:"\");

registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach subkey (make_list("InstallLocation", "Inno Setup: App Path"))
{
  item = get_registry_value(handle:hklm, item:key + "\" + subkey);
  if (!empty_or_null(item))
  {
    path = item;
    break;
  }
}

# Grab putty dir from newer installs, e.g., 0.70
if (isnull(path))
{
  key = "SOFTWARE\Classes\PPK_Assoc_ProgId\shell\edit\command\";
  item = get_registry_value(handle:hklm, item:key);
  if (!empty_or_null(item))
  {
    # "C:\Program Files\PuTTY\puttygen.exe" "%1"
    path = item - '\\puttygen.exe" "%1"';
    path = substr(path, 1);
  }
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (empty_or_null(path))
  audit(AUDIT_UNINST, app);

file = hotfix_append_path(path:path, value:"putty.exe");

if (!hotfix_file_exists(path:file))
  audit(AUDIT_UNINST, app);

fversion = hotfix_get_fversion(path:file);
if (fversion.error == HCF_OK)
{
  version = join(fversion.value, sep:'.');
}
else
{
  # old versions don't have file version
  # so we search for a specific pattern in the exe
  file_contents = hotfix_get_file_contents(path:file);
  if (file_contents.error != HCF_OK)
    audit(AUDIT_VER_FAIL, file);

  # strip nulls
  blob = str_replace(string:file_contents.data, find:raw_string(0), replace:" ");

  # This pattern has been verified for versions 0.53 - 0.58.
  pattern = "PuTTY-Release-([a-zA-Z0-9.]+)";

  lines = pgrep(string:blob, pattern:pattern);
  foreach line (split(lines))
  {
    matches = pregmatch(string:line, pattern:pattern);
    if (!isnull(matches))
    {
      version = matches[1];
      break;
    }
  }
}

if (version == UNKNOWN_VER)
  audit(AUDIT_VER_FAIL, file);

register_install(
  vendor:"Simon Tatham",
  product:"PuTTY",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:simon_tatham:putty"
);

hotfix_check_fversion_end();
report_installs(app_name:app);
