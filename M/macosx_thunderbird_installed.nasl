#TRUSTED 989e9b9dd68f1067413e4e91ad94d94f34ac1946c6a0c1ff8ed3c397ff9283268ec2f5de56d01fd5d0ec7d1687df82a615364d2377428c881643cb4a1dc9ad6866d99e233b8d6036e4cafa5bb0a9d01daad0a6bea3c7396e76bf25335b3ec94b96277ad7dea63cb0479f7dffb1bc423f93153953a3ab5580e83099505ff847e4d3040440f61b349c10c0feae1dc0bf7655ebf93d10d2c5f5aed42f6fdd6896399b622deb83ee650cce635c8981d6f5888e5ca7735b6f9690758cff241a06cc2837b859b2a2193d4666b027c3efc1c305bfe589bac22e4f3a3946584a5bbbbedd7e18ae2a1d5666759a9c83be5ac851f530fd0a9fa1806abbfcd3c9516b45e7882db170fa0c9aafd3b3067b9a612592a9fa7919109163378f946cd7f6c6cc4ed174344f0048ff1d233232c953d30315b1bbf21fc39a68c93294f052c6816f304726f1861ec46d414a22cea6f8a116de8ea2011f60d560d96bbd7379afdf5b64f15a819ebc6ae94faa7ea296aaa3023ecdfafe05d58edaf7a7280b11a3d458b7b0cd294ae36cec848c7df1c701755a2b30e3ce0ba3ddbd34eb62bfab835141857d4bcb3466c7e55ad5e46b5c30f56bd88cdcd71c9f19554dd325490b3ce2a0c6e5e6dc440b86a3efe83816b105ae3a2450647334396ac93ceb70daf1263f0adc257c6065c5c2762eec24e2458367eee2be580c96cc265b3a666926c7a11205dbd3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56557);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_xref(name:"IAVT", value:"0001-T-0730");

  script_name(english:"Thunderbird Installed (Mac OS X)");
  script_summary(english:"Gets the Thunderbird version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an alternative email client.");
  script_set_attribute(attribute:"description", value:
"Mozilla Thunderbird is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/thunderbird/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

app = "Thunderbird";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


kb_base = "MacOSX/Thunderbird";

path = '/Applications/Thunderbird.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);
set_kb_item(name:kb_base+"/Version", value:version);

# Set path here so if, in the future, locations
# change on Mac, we can detect and use this variable
# and KB item in version checks.
set_kb_item(name:kb_base+"/Path", value:path);
orig_version = version;

# Check if ESR
var sw_edition = NULL;
esr_major_versions_pattern = "^(17\.)";
if (version =~ esr_major_versions_pattern)
{
  xul_file = path + '/Contents/MacOS/XUL';
  cmd = 'grep -ie "esr.releasechannel" '+xul_file;
  is_esr_res = exec_cmd(cmd:cmd);

  if (strlen(is_esr_res))
  {
    if (is_esr_res =~ "^Binary file.*\/XUL matches")
    {
      is_esr = " ESR";
      set_kb_item(name:kb_base+"/is_esr", value:TRUE);
      version += " ESR";
      sw_edition = 'ESR';
    }
  }
}

register_install(
  app_name:app + is_esr,
  vendor : 'Mozilla',
  product : 'Thunderbird',
  sw_edition : sw_edition,
  path:path,
  version:orig_version,
  cpe:"cpe:/a:mozilla:thunderbird"
);

report_installs(app_name:app + is_esr);

