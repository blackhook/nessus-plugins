#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64937);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"Nuance PDF Reader Installed");
  script_summary(english:"Checks for a Nuance PDF Reader install");

  script_set_attribute(attribute:"synopsis", value:"A PDF file viewer is installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"Nuance PDF Reader, a free PDF file viewer, is installed on the remote
host."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.nuance.com/print-capture-and-pdf-solutions/pdf-and-document-conversion/pdf-reader.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nuance:pdf_reader");
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

get_kb_item_or_exit('SMB/Registry/Enumerated');

appname = "Nuance PDF Reader";
registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\PDFReader.exe";
item = get_values_from_key(handle:handle, key:key, entries:make_list('Path'));
path = item['Path'];
RegCloseKey(handle:handle);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

filePath = path + "\VideoPlayer.dll";
ver = hotfix_get_fversion(path:filePath);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
{
  filePath = path + "\PDFReaderHBISImpl.dll";
  ver = hotfix_get_fversion(path:filePath);
  hotfix_check_fversion_end();
  if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
}

if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, filePath);

ver2 = ver['value'];
version = ver2[0] + '.' + ver2[1];
version_full = join(ver2, sep:".");

port = kb_smb_transport();
kb_base = "SMB/Nuance_PDF_Reader/";

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Version_full", value:version_full);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:appname,
  vendor : 'Nuance',
  product : 'PDF Reader',
  path:path,
  version:version,
  extra:make_array("Full Version", version_full),
  cpe:"cpe:/a:nuance:pdf_reader");

report_installs(app_name:appname, port:port);

