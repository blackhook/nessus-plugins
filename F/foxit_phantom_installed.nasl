#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49807);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_xref(name:"IAVT", value:"0001-T-0604");

  script_name(english:"Foxit PDF Editor (PhantomPDF) Detection");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Foxit PDF Editor (formerly known as PhantomPDF and Phantom), a free PDF toolkit, is installed on the remote Windows
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/pdf-editor/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var prods = make_nested_list(
  make_array(
    "key",  make_list("SOFTWARE\Foxit Software\Foxit Phantom","SOFTWARE\Wow6432Node\Foxit Software\Foxit Phantom"),
    "name", "Phantom",
    "exe",  "Foxit Phantom.exe",
    "cpe",  "phantom",
    "paths", make_list()
  ),

  make_array(
    "key",  make_list("SOFTWARE\Foxit Software\Foxit PhantomPDF","SOFTWARE\Wow6432Node\Foxit Software\Foxit PhantomPDF"),
    "name", "PhantomPDF",
    "exe",  "regkey",
    "cpe",  "phantompdf",
    "paths", make_list()
  ),

  make_array(
    "key",  make_list("SOFTWARE\Foxit Software\Foxit PDF Editor","SOFTWARE\Wow6432Node\Foxit Software\Foxit PDF Editor"),
    "name", "PDF Editor",
    "exe",  "regkey",
    "cpe",  "phantompdf",
    "paths", make_list()
  )
);

registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

var found = 0;
var path;

for (var i=0; i < max_index(prods); i++)
{
  foreach var key (prods[i]["key"])
  {
    path = get_registry_value(handle:hklm, item:key + "\InstallPath");
    # Newer installs store the binary name in the registry
    var exe;
    if (prods[i]["exe"] == "regkey")
    {
      exe = get_registry_value(handle:hklm, item:key + "\InstallAppName");
    }
    else
    {
      exe = prods[i]["exe"];
    }
    if (path && exe)
    {
      prods[i]["paths"] = make_nested_list(list:prods[i]["paths"], path + exe);
      found++;
    }
    else
      continue;
  }
}

if (!found)
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "Foxit Phantom/Foxit PhantomPDF");
}

var report = FALSE;
foreach var prod (prods)
{
  if (!max_index(prod["paths"]))
    continue;

  foreach path (list_uniq(prod["paths"]))
  {
    var version = hotfix_get_fversion(path:path);

    if (version['error'] == HCF_OK)
      version = join(version['value'], sep:'.');
    else
      version = UNKNOWN_VER;

    register_install(
      app_name:"FoxitPhantomPDF",
      vendor : 'Foxit',
      product : 'PhantomPDF',
      path:path,
      version:version,
      cpe:"cpe:/a:foxitsoftware:" + prod["cpe"]
    );

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
  audit(AUDIT_NOT_INST, "Foxit Phantom/Foxit PhantomPDF");
