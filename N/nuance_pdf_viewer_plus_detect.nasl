#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64938);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Nuance PDF Viewer Plus Installed");
  script_summary(english:"Checks for a Nuance PDF Viewer Plus install");

  script_set_attribute(attribute:"synopsis", value:"A PDF file viewer is installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"Nuance PDF Viewer Plus is installed on the remote host.  Nuance PDF
Viewer Plus is a PDF file viewing component of Nuance PaperPort, which
is a commercial document management application.

Note that this plugin only checks for the presence of Nuance PDF Viewer
Plus."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.nuance.com/print-capture-and-pdf-solutions/optical-character-recognition/paperport-for-pc.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nuance:paperport");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nuance:pdf_reader_plus");
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
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

appname = "Nuance PDF Viewer Plus";
key = NULL;
list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
foreach name (keys(list))
{
  prod = list[name];
  if("Nuance PDF Viewer" >< prod)
  {
    uninstall = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:uninstall);
    break;
  }
}

if (isnull(key)) audit(AUDIT_NOT_INST, appname);

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
item = get_values_from_key(handle:handle, key:key, entries:make_list('InstallLocation'));
path = item['InstallLocation'];
RegCloseKey(handle:handle);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

filePath = path + "\PDFEngine.dll";
ver = hotfix_get_fversion(path:filePath);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, filePath);

version = join(ver['value'], sep:".");

port = kb_smb_transport();
kb_base = "SMB/Nuance_PDF_Viewer_Plus/";

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:appname,
  vendor : 'Nuance',
  product : 'PDF Reader Plus',
  path:path,
  version:version,
  cpe:"cpe:/a:nuance:paperport");

report_installs(app_name:appname, port:port);

