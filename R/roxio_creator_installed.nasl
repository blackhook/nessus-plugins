#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70143);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Roxio Creator Installed");
  script_summary(english:"Checks if the Roxio Creator is installed");

  script_set_attribute(attribute:"synopsis", value:"A media creation application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Roxio Creator, a media creation and optical disc authoring application,
is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.roxio.com/en/products/creator/suite/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:roxio:easy_media_creator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:roxio:creator");
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
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

kb_base = "SMB/roxio_creator/";
appname = "Roxio Creator";

# Add more as needed
branches = make_list('9', '10');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach branch (branches)
{
  install_path = get_registry_value(handle:hklm, item:"SOFTWARE\Roxio\Creator Classic\" + branch + ".0\installpath");
  if (!isnull(install_path)) break;
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (isnull(install_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

file_path = install_path + "Creator" + branch + ".exe";
ver = hotfix_get_fversion(path:file_path);
hotfix_check_fversion_end();

if (ver['error'] == HCF_OK)
  version = join(ver['value'], sep:'.');
else
  audit(AUDIT_VER_FAIL, file_path);

if (!isnull(version))
{
  set_kb_item(name:kb_base + "Installed", value:TRUE);
  set_kb_item(name:kb_base + "Path", value:install_path);
  set_kb_item(name:kb_base + "Version", value:version);

  register_install(
    app_name:appname,
    vendor : 'Roxio',
    product : 'Creator',
    path:install_path,
    version:version,
    extra:make_array('File', file_path),
    cpe:"cpe:/a:roxio:easy_media_creator");

  report_installs(app_name:appname, port:port);
}
else audit(AUDIT_UNINST, appname);
