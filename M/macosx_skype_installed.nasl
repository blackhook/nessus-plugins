#TRUSTED aba2f3eadece5d8b744ad47a56acb0f7484b99411544fd3ff8eb57b462958915d05578f942a75eb65d8ac674a719584c536de570b0ea41f1a9bdc96fcf25527ae9aeb441e34684df0454a43b6dfba7de41a829b40cc0925a81eaa29b06582ec45b7c3017cfb72609efc710ef9ffd68d44a233e3edde8794ed4150192dd6571123a9531e03e65b66c7e49adebe0c030a226138f4eae0e874621a2e2e843b4aa515c8d4d94342c568f669ac8570b68bc94005a5d4e381a64e7e839f8955d4920d47c0b1883302d5887ccf321d0e08eadb0901dcca2c9cf2d6948123a90cade3935dff4990df005bf63ace84283da1ead7301da7d8de3b084012758e3c400f60b380e6d7ddc3d710c027f184c03c84929eb274513673001e3e058e79a43d8af928276ae1215d61333b56e3016ca46490d1a50d956c7968a205f4a7621d6fc78c86065592e4ed75e28a3b7a72b2b3a08f91a88207bddc6a34f9893e2139012a6930385ea8255cb278bdd09daf82f0cdd5fd6114cba7a6b3698b7f37fbec934faadee33076682698d399d284955e288e2fe71674293edef65eb7bcf29d68383d43a6d4402664b2e60cfed21467b417ca78ba7a327a21738016640e951192988fbe1e76035775dfe409f9d15b72713d32f0f226929b4a1f2ed8187e7786b1356ad80ed7ee24e4a9f5b555abb2539b74930dce3b66d18d30d3db217c5d747e496b146a9
#TRUST-RSA-SHA256 1edb415d27fafcd325140dd48b8a71b589966127976e2a01ebdc81eebef717a3bd5a8081c4dc1438630f0dcc33990dcfe6655ac28c15211172f79a97319f1efa14e97310dce65eade5602fdeea09162c14c80e596adc1b89021b986bedee1a3657a2f320e367d21e5d86c8c4c3fe61e83fd37a1c1619842cf25bf3ca3e18727669f2909856bd701d51e59575898be940d23c257abf3721d38c155e2240925258a8fc35abd25b048f433304614506cd645ba8f2693e409a6694cba63ee3bc0e717f60bc1b18fd179a16f3186992e47a668bf960189fccc59bac1ab5320243dd78a550b23392fe0c932a260639c93218f3bb4b884428bd455f79a1b404a27a8280eaad002250d830957b4c4923889f68cab62b964c81f71e0d320aaf9a9d166893ecb49c2a39e3f7c6bb5b810a7cb611395f4d2c48aba772a3ebd3e6b459c75184f5ac01465afa9757d21f0c5dc86c7d4563871af17385228d0ab70b62f186c86f88f5db7e71050720a6fb3a72ca4d4c12d0f81354f5c16c97a9b24898b71d6307efdd96af0401d94ef63e6c521b66d4401072eed29167c6de5c0813814b78e1ffb1259ed9da303f30904ae5b11d69f0dbe2761831faa7a5d95df0d02f9389fd10d680af4b737149160bc50cbdedac28e8ae479d73e5082dc32943fd68a04fb9b3fa5a17e4c508b3f85e8c0dcfdd14b8080d21f0831115af2411475b23efe97ac6
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(53843);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Skype for Mac Installed (credentialed check)");
  script_summary(english:"Gets Skype version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:"Skype is installed on the remote Mac OS X host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Skype, a peer-to-peer Voice Over IP application, is installed on
the remote Mac OS X host.

Due to the peer-to-peer nature of Skype, any user connecting to the 
Skype network may consume a large amount of bandwidth."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.skype.com/MacSkype"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("global_settings.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

plist = "/Applications/Skype.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec_cmd(cmd:cmd);
if(isnull(version)) exit(0, "Skype is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

# nb: older versions (eg, 1.3.0.14) have their version info in a different spot.
if (version =~ "^0\.")
{
  cmd = string(
    "cat '", plist, "' | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version2 = exec_cmd(cmd:cmd);
  if(version2 =~ "^1\.") version = version2;
}
set_kb_item(name:"MacOSX/Skype/Version", value:version);

gs_opt = get_kb_item("global_settings/report_verbosity");
if (gs_opt && gs_opt != 'Quiet') security_note(port:0, extra:'\n  Version : ' + version + '\n');
else security_note(0);

app = "Skype";
path = "/Applications/Skype.app"; 
cpe = "cpe:/a:skype:skype";

register_install(
  vendor   : "Skype",
  product  : "Skype",
  app_name : app,
  version  : version,
  path     : path,
  cpe      : cpe
);
