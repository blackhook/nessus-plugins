#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62624);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Investintech Able2Extract Detection");
  script_summary(english:"Checks for install of Able2Extract");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a PDF converting application installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an install of Investintech Able2Extract, a PDF
converter."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.investintech.com/prod_a2e.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:investintech:able2extract");
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

port = kb_smb_transport();
appname = 'Investintech Able2Extract';
kb_base = "SMB/Investintech_Able2Extract/";

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

paths = make_array();
errors = make_list();

in_registry = FALSE;
foreach key (display_names)
{
  if ('Able2Extract' >< key) in_registry = TRUE;
}

if (!in_registry) audit(AUDIT_NOT_INST, appname);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if ("Able2Extract" >< display_name)
  {
    key -= '/DisplayName';
    key -= 'SMB/Registry/HKLM/';
    key = str_replace(string:key, find:"/", replace:"\");

    install_location_key = key + "\InstallLocation";
    uninstall_key = key + "\UninstallString";

    path = get_registry_value(handle:hklm, item:install_location_key);
    if (isnull(path))
    {
      path = get_registry_value(handle:hklm, item:uninstall_key);
      if (isnull(path)) continue;

      item = eregmatch(pattern:"([a-zA-Z]:\\.*\\)", string:path);
      if (isnull(item)) continue;
      path = item[1];
    }

    if ("Professional" >< display_name) paths[path] = 'Able2ExtractPro.exe';
    else paths[path] = 'Able2Extract.exe';
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

num_installs = 0;
report = '';

foreach path (keys(paths))
{
  exe = path + paths[path];
  ver = hotfix_get_fversion(path:exe);

  if (ver['error'] != HCF_OK)
  {
    # file does not exist, so application must have been
    # uninstalled uncleanly
    if (ver['error'] == HCF_NOENT) continue;

    if (ver['error'] == HCF_CONNECT) exit(1, "Unable to connect to remote host.");

    share = hotfix_path2share(path:exe);

    if (ver['error'] == HCF_UNACCESSIBLE_SHARE)
      errors = make_list(errors, "Unable to access the file share '" + share + "'.");
    else if (ver['error'] == HCF_NOAUTH)
      errors = make_list(errors, "Error accessing '" + exe + "'. Invalid credentials or share doesn't exist.");
    else if (ver['error'] == HCF_NOVER)
      errors = make_list(errors, "File version does not exist for '" + exe + "'.");
    else
      errors = make_list(errors, "Unknown error when attempting to access '" + exe + "'.");
    continue;
  }
  version = join(sep: '.', ver['value']);

  is_pro = FALSE;
  if ("Pro" >< paths[path]) is_pro = TRUE;

  set_kb_item(name:kb_base + num_installs + "/Path", value: path);
  set_kb_item(name:kb_base + num_installs + "/Version", value: version);
  set_kb_item(name:kb_base + num_installs + "/IsPro", value: is_pro);

  register_install(
    app_name:appname,
    vendor : 'Investintech',
    product : 'Able2Extract',
    path:path,
    version:version,
    extra:make_array('IsPro', is_pro),
    cpe:"cpe:/a:investintech:able2extract");

  num_installs++;
}

hotfix_check_fversion_end();

if (num_installs)
{
  set_kb_item(name:kb_base + "Installed", value: TRUE);
  set_kb_item(name:kb_base + "NumInstalls", value: num_installs);

  if (max_index(errors))
  {
    report +=
      '\n' +
      'Note that the results may be incomplete because of the following ';

    if (max_index(errors) == 1) report += 'error\nthat was';
    else report += 'errors\nthat were';

    report +=
      ' encountered :\n' +
      '\n' +
      '  ' + join(errors, sep:'\n  ') + '\n';
  }

  report_installs(app_name:appname, port:port, extra:report);
  exit(0);
}
else
{
  if (max_index(errors))
  {
    if (max_index(errors) == 1) errmsg = errors[0];
    else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

    exit(1, errmsg);
  }
  else audit(AUDIT_UNINST, appname);
}
