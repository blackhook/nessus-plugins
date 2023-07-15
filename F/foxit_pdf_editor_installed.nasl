#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65613);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Foxit Advanced PDF Editor Installed");
  script_summary(english:"Checks for a Foxit Advanced PDF Editor install");

  script_set_attribute(attribute:"synopsis", value:"A PDF file editor is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Foxit Advanced PDF Editor (formerly known as Foxit PDF Editor), a PDF
file editor, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/pdf-editor/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_advanced_pdf_editor");
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

kb_base = "SMB/Foxit_pdf_editor/";
appname = "Foxit Advanced PDF Editor";
key = "SOFTWARE\Foxit Software\Foxit Advanced PDF Editor";
list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
uninstall_keys = make_list();

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
item = get_values_from_key(handle:handle, key:key, entries:make_list('AppFileName'));
installPath = item['AppFileName'];

foreach name (keys(list))
{
  prod = list[name];
  if ("Foxit PDF Editor" >< prod || "Foxit Advanced PDF Editor" >< prod)
  {
    installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:installstring);
    uninstall_keys = make_list(uninstall_keys, key);
  }
}

products = make_array();
foreach uninstall (uninstall_keys)
{
  values = get_values_from_key(handle:handle, key:uninstall, entries:make_list('DisplayName', 'InstallLocation', 'UninstallPath'));
  prod = values['DisplayName'];
  path = values['InstallLocation'];
  if (strlen(path) > 0) products[path] = prod;
  else if (strlen(values['UninstallPath']) > 0)
  {
    uninstall_path = values['UninstallPath'];
    path = eregmatch(string:uninstall_path, pattern:"(.*\\)(.*.exe)");
    if (!isnull(path))
    {
      path = path[1];
      products[path] = prod;
    }
  }
}

RegCloseKey(handle:handle);
if (max_index(keys(products)) == 0 && isnull(installPath))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

install_count = 0;
ver_fail = TRUE;
if (hotfix_file_exists(path:installPath))
{
  path = eregmatch(string:installPath, pattern:"(.*\\)(.*.exe)");
  if (isnull(path)) path = installPath;
  else path=path[1];
  ver = hotfix_get_fversion(path:installPath);
  if (ver['error'] == HCF_OK)
  {
    ver = ver['value'];
    version = join(ver, sep:".");

    replace_kb_item(name:kb_base + "Path", value:path);
    replace_kb_item(name:kb_base + path + "/Version", value:version);
    replace_kb_item(name:kb_base + path + "/Appname", value:appname);

    register_install(
      app_name:appname,
      vendor : 'Foxit',
      product : 'Advanced PDF Editor',
      path:path,
      version:version,
      cpe:"cpe:/a:foxitsoftware:foxit_advanced_pdf_editor");

    install_count += 1;
    ver_fail = FALSE;
  }
}

foreach path (keys(products))
{
  if ("Foxit PDF Editor" >< products[path]) file = path + "PDFEdit.exe";
  else if ("Foxit Advanced PDF Editor" >< products[path]) file = path + "Foxit Advanced PDF Editor.exe";

  if (!hotfix_file_exists(path:file)) continue;

  ver = hotfix_get_fversion(path:file);
  if (ver['error'] == HCF_OK)
  {
    ver_fail = FALSE;
    version = join(ver['value'], sep:".");
    set_kb_item(name:kb_base + "Path", value:path);
    replace_kb_item(name:kb_base + path + "/Version", value:version);
    replace_kb_item(name:kb_base + path + "/Appname", value:products[path]);
  }
}

hotfix_check_fversion_end();
if (ver_fail && !install_count) exit(1, "Failed to get the file version.");

set_kb_item(name:kb_base+"Installed", value:TRUE);

port = kb_smb_transport();

report_installs(app_name:appname, port:port);

