#TRUSTED 80e102cf4846e9783f6daca125e44bf0d16806afc7d2769952c50c41a4acd2fc4f1b1c5a62dc62d1b6e414ea273a8c67393960418ef675f1b146f4b3e036957dce1bc70646bbcc53016ef6b6edd10cd6372811ecae334f35eac5d81efdbaa380bf65cb044bfbba9369c51dbe087c72a7d8af59e1782b8256cb91066c0355465fa019931735a2b077e7d847d373254ce16e429c559e7e859f6159bf83c66146eb9bf01fe26a195b7477fbb7993c5c813f0b0854aacee7dd12e5a05738f04683076bee45448e23fcc609882e51bf85d09d7e8b09d2b8f3d5ecac3f4cb529904f68b8a21a8bda4f40fd516c77406363584d1a2336bd4d0fd22c82ed242aebb94e5f134ffee8b5b33f2d5ce16206cfca21735d0848acde567fcce5249d0554135c05c5841e83f18e9b102ebece51f34354369a2185e98511522432eb1e95332948b3d23cd8d67a56590488a02551853b6afca57403fa118e4b2fb24a7961522609004326bb63d71e59f5ed00c6ccf25f24a11ed5a651a16b70223216657e6fa7932966ffcb82d3b76661262869baea3dd737d13e163a53a4b018c43cb1bc526dad24b4164db1a26fdc9b2182138d248c72ef5ec08b9c5d4cee7936816436df2380a44051ad3ac419723b9572d9e8b39a37424e0352c686a3fe66ac2f47dcd3578d991bcc61921accf6d84c12c3a2a64bc3510c988e5a42f38b489c7d19ad77155187
#TRUST-RSA-SHA256 8852cc77064be5bc3408a61a2cd2a300b5e7805cd6a9efff47074f74e640edaca92c60f84590203b6d2c9bd2c912d2668bd262d6cfb347f62c1b686dc9c9982df9b6131cad3f49fd3c53e67a376cc3a0434228823c75a521f5711f1a1c1d91ffb95d245d5c9e3ea94d724a8862c266d299c1c4f47513144f02c12336727446c34e50662eea9a6f34f846f26ee6aa47abccf34cec795fc7e8fa0f1b6f1c86ac82e4e8a5a541d661bd590c4c1fdf8ce0d45942181741f584f37bcbe0b7ebb9aa1250659d27c7e39ff7cb37e27feaba2f7c49e21de3841dab5424e6953b55f7703e410b36e42b2aecbe4107cc7d35c1bd9e8fe5265749c77675b7d3adc568e73ad6c50e1eaee4a20fddcbff2fa581a3023f6a89bbbd7a66cf6e7d671e95f47c101e82070441feeebecc3396c967277171a9069224f9631d180fef8ffd9e5511a8fb3fa6804f143dc8a6cea10b2a251e0db88a2bf28b4188caa6068644ede1d4451786cfc5f1d0888bac648b201b43d6dea693e579f25f7788091427cf37b066d967b68efc35500715f03b79456b424ef015ea6c3e203da3782968215c61846e3cbf9c7b1ea3052fe162707c3951744a90ee3e604868048eba858fc817698b0afe54e0a123c8805cade9e97152ddc90deaf8c9da7f5b6b184133fc067c1e74f78adb7575acf5e991da15568109cc5b5e58422e87b15d860b16ea05dd2aeecbfd9199
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58291);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Evernote Installed (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"A cloud-based note taking application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Evernote is installed on this host. It is a cloud-based suite of
software for note taking and archiving.");
  script_set_attribute(attribute:"see_also", value:"http://www.evernote.com/evernote/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:evernote:evernote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");

app = "Evernote";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Evernote";


path = '/Applications/Evernote.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Evernote does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The Evernote version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  vendor:"Evernote",
  product:"Evernote",
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:evernote:evernote"
);

report_installs(app_name:app);

