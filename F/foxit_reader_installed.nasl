#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32395);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0605");

  script_name(english:"Foxit Reader Detection");
  script_summary(english:"Checks for Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Foxit Reader, a free PDF file viewer, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/pdf-reader/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("install_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var name = "Foxit Reader";

# All of the currently know registry paths
var regkeys = make_list(
            "SOFTWARE\Foxit Software\Foxit Reader",
            "SOFTWARE\Wow6432Node\Foxit Software\Foxit Reader",
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Foxit Reader_is1",
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foxit Reader_is1",
            "SOFTWARE\Foxit Software\Foxit PDF Reader",
            "SOFTWARE\Wow6432Node\Foxit Software\Foxit PDF Reader");

# All of the current known executable names
var exes = make_list("FoxitReader.exe", "Foxit Reader.exe", "FoxitPDFReader.exe");

registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

var found = 0;
var paths = make_list();
var path;
foreach var key (regkeys)
{
  path = get_registry_value(handle:hklm, item:key + "\InstallPath");
  # Account for strange 5.4 installs. This is the uninstall hive.
  if (!path)
    path = get_registry_value(handle:hklm, item:key + "\InstallLocation");

  if (path)
  {
    # Normalize the string to avoid duplicates
    # ie- path and path\
    if (ereg(string:path, pattern:".*\\$"))
    {
      var matches = eregmatch(string:path, pattern:"^(.*)\\$");
      if (!isnull(matches))
        path = matches[1];
    }

    paths = make_list(paths, path);
    found++;
  }
  else
    continue;
}

if (! found)
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, name);
}

var report = FALSE;

foreach path (list_uniq(paths))
{
  foreach var exe (exes)
  {
    var version = hotfix_get_fversion(path:path +"\"+ exe);

    if (version['error'] != HCF_OK)
      continue;

    version = join(version['value'], sep:'.');

    register_install(
      app_name:name,
      vendor : 'Foxit',
      product : 'Foxit Reader',
      path:path,
      version:version,
      cpe:"cpe:/a:foxitsoftware:foxit_reader");

    report = TRUE;
  }
}

RegCloseKey(handle:hklm);
close_registry();

if (report)
{
  var port = kb_smb_transport();
  report_installs(port:port);
}
else
  audit(AUDIT_NOT_INST, name);
