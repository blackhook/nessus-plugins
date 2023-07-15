#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63112);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_name(english:"VMware Movie Decoder Installed");
  script_summary(english:"Checks for a VMware Movie Decoder install");

  script_set_attribute(attribute:"synopsis", value:"A movie decoder is installed on the remote Windows host.");
  script_set_attribute( attribute:"description", value:
"VMware Movie Decoder, which is used to play movies recorded by VMware
Workstation, is installed on the remote Windows host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:movie_decoder");
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
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");

app = "VMware Movie Decoder";

list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

decoder_installed = FALSE;
foreach name (list)
{
  if (name == 'VMware Movie Decoder')
  {
    decoder_installed = TRUE;
    break;
  }
}
if (!decoder_installed) audit(AUDIT_NOT_INST, app);

hotfix_check_fversion_init();

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

path = rootfile + "\system32";
file = path + "\vmnc.dll";
ver = hotfix_get_fversion(path:file);
hotfix_check_fversion_end();

if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, file);
version = join(ver['value'], sep:".");

port = kb_smb_transport();
kb_base = "SMB/VMware Movie Decoder/";

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "File", value:file);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:app,
  vendor : 'VMware',
  product : 'Movie Decoder',
  path:path,
  version:version,
  extra:make_array('File', file),
  cpe:"cpe:/a:vmware:movie_decoder");

report_installs(app_name:app, port:port);

