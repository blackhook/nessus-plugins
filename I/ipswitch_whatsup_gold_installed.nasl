#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62185);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Ipswitch WhatsUp Gold Detection");
  script_summary(english:"Detects installs of Ipswitch WhatsUp Gold");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has network management and monitoring software
installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has an install of Ipswitch WhatsUp Gold, a
web-based network management and monitoring tool."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.whatsupgold.com/products/whatsup-gold-core/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

kb_base = "SMB/Ipswitch_WhatsUp_Gold/";
appname = 'Ipswitch WhatsUp Gold';
version_key = "SOFTWARE\Ipswitch\Network Monitor\WhatsUp Gold\Setup\Version";
install_key = "SOFTWARE\Ipswitch\Network Monitor\WhatsUp Gold\Setup\InstallDir";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
ver_ui = get_registry_value(handle:hklm, item:version_key);
path = get_registry_value(handle:hklm, item:install_key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

close_registry(close:FALSE);

exe = path + "\NmConsole.exe";
ver = hotfix_get_fversion(path:exe);

if (ver['error'] != HCF_OK)
{
  NetUseDel();

  # file does not exist, so application must have been
  # uninstalled uncleanly
  if(ver['error'] == HCF_NOENT)
     audit(AUDIT_UNINST, appname);

  # other error
  exit(1, "Error obtaining version of '" + path + "\NmConsole.exe'");
}

hotfix_check_fversion_end();

version = join(ver['value'], sep:'.');
if (empty_or_null(ver_ui))
{
  ver_ui = ver['value'][0] + '.' +
         ver['value'][1] + '.' +
         ver['value'][2];
}

set_kb_item(name:kb_base+"Installed", value:TRUE);
set_kb_item(name:kb_base+"Version_NmConsole", value:version);
set_kb_item(name:kb_base+"Version_UI", value:ver_ui);
set_kb_item(name:kb_base+"Path", value:path);

register_install(
  app_name:appname,
  vendor : 'Ipswitch',
  product : 'WhatsUp Gold',
  path:path,
  version:version,
  cpe:"cpe:/a:ipswitch:whatsup_gold");

port = get_kb_item('SMB/transport');
report_installs(app_name:appname, port:port);

