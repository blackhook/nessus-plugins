#TRUSTED 80d08cd3d1971c43cc69659ca2bcac9609e0340f8d5cf98fa91debff46bb5b834d03329215207f53a732e6e04a508dd1e64eda840de758603c59cb765e1bd90223e8cf28f33aa1e8c464d4a4da018f3b0cee0cd0963d5377f2a7e0647fdca01a021b815599c5feee5c1e092f483af061e022fbc5c8d0afadc8310179e92f9b33d01941304fc697e35dc38f01900a8a3c3dc0c80bbc0d0a09e20b8df4b5e569ded2268b9759264c35f37d0a32495ca1388f2b8d900082b3daac694ec52aab10c311b2ae08a6a847244a082e858f623ddc1b140899a2649d00f6534f3e8dc807b3d9f9a060f00f927418cef6f2f8e539b9949c0d2c6cbf8b7f3be72452ed758ef5aeecce487f045b5eddc7a1dd94d027e14d9e09631ce8f01c0198e2f9d81933ba9e9d9f8999a6fab713321d4bda4ca7a74a0478cccdf0a23432e0b36ee2a1b28b9d4de541e7e76e8ca403c9aaa80160dc58d2b9200ff92d4cead6d06e93feaec4cc510db13c302553a3bba5211b040536ad494c4ad8ba4d1a374ef6733529af17d5a9de35570fb6e510031439ba9df1f3704c190191d15df95b21faca5d0e74d799c71c7597e3304266ad613a545ba4412fab4bd3066276eb4a10e71afa3cd887880204a8d583786b17bce154fd92f8b407473be4f8a8655307263b77acb8eb0558513af3b8ef28be39030a7838591ef4ccd483651a91b5c33a56bd10f0c63e65
#TRUST-RSA-SHA256 46bcc2252ebed671832178edb6f15a1342e2be6a9b3d8ba4261570a27e3d0b2adff16fc15a675eede90528188da53a62c2b21e7e7b62694821030c716e97058134e3ee698505ae162bb2d1cda73b0aba89a00430506033164ca45d47b881410b63ab6100310d472226a382eb37dcf0f0ff1931ff0cab4c56749736e01dbeb493eddf6198a04d7234a935ef83846eceb197bbcb89d10852db39ac97dec5af76b9a68dfcd95de4995ccdc302deb793e893d51f063114e9db9d838af264f74d9e603330e181cde20ed5642b9a463b12c57bbd53d853c9cf21fb365889aa6baf1d9e0041345b0a08dfd8dc002cc08cc93d4f0e6c1a6581c3083823dc05acc940a5b02d8af2896af6f635b0c244e36a9bc5c0b19773e5fd85594c69e3d75601cfcd3069214b9ef8375a741b1c27dd18bb7a22fb60cceee242ce2ff29094f38f166c6dda03c670a52b1cbff03dcc450cbbcc9497d2e6adc869e579d292c64f3ca2c243286f3d9a6aba6100809e67b78f6b849ed54e4cbc083e820acccdba45242cfe5d415730c66b01fab90ce3816db9bac08c43f295954657be0a032bcb97eaaa18d2649efcaa3d8007efd9af2ac98833a9b59e3a2178602370430855d317e2b7feae763599b58f46d291c8dd99a9fc3c484c5da91a67f3411dadca9add80636d55034fcf25edff860edfdbd8285b307f2e2e2fff65679b66b8cc2f276b2d0105719b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65699);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_xref(name:"IAVT", value:"0001-T-0918");

  script_name(english:"Viscosity VPN Client Detection (Mac OS X)");
  script_summary(english:"Detects Viscosity VPN Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a VPN client installed.");
  script_set_attribute(attribute:"description", value:"The remote host has the Viscosity VPN client installed.");
  script_set_attribute(attribute:"see_also", value:"http://www.sparklabs.com/viscosity/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sparklabs:viscosity");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

app = "Viscosity";

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

kb_base = "MacOSX/Viscosity";

path = '/Applications/Viscosity.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' 2>/dev/null | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, app);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, app);
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  vendor:"SparkLabs",
  product:"Viscosity",
  app_name:app,
  path:path,
  version:version,
  cpe:"x-cpe:/a:sparklabs:viscosity");

report_installs(app_name:app);

