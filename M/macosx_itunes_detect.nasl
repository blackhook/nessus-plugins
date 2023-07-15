#TRUSTED 6d80f7cfcfe64fc9c1609f619459cd8378dc7c6f4b8d21fe84f4fc16e7437f2ec5f88b65fdf283f00ba06fa8e2915b836f39efb7c1f60008654af40948e5bb3cb209817c022b65d6ebc6bae6194cd99f2f2a855c1025cb725aaa8b3b4302cbcb1b74817982bed5b40951b94a0005c07240f8d61579c3420a18e643be8df4bf09bbe4c18dbcf4b3e641c0027fe6fc8368ecb2297ec422238334d7d86028bba16ba429acebda68bc2e7f88257e5ea1f7d227f95845cb45a0cf747a9259a919ec8c2240f6ab9955b4112a4c102298deffd64ff258548a1b10a85552abff514d6d06bc6625bcb04a78ace839b1d6d818b8a8e9cd627754805adfbc80b20f8f56dae1d11c01e56132db594689014c4356a657356b5ea7aaa06dd10aeb44108726ea3aabbc5d2e929609701d8ef432ecb32d4acd07f1cc8a1cc7a694c8dc009ee9fa8551d3dfae448c38b714c257b29a6aed528843bb6d263a297cfeda6c8fb9fab89ce1682802b3ee0017e087d56f53262927171abd3a39b078ebd4135f892ca833be6ad5ea580e1cb156c24830f24de723ec77efaf547926f0a4c23be248fa13550af9f412ab290fed79f517f94e5d002c1d3659ae76f40000b1d2f43f102e8b683221c24f93904d1550714c8e100c5af8b0b20d97085c443335381550a2ff1a228fd9d105cf34d5fc51d9f315cb37f99146cf5808f0f516baf2ef9e50c70ad74346
#TRUST-RSA-SHA256 5c95267a5f3aa22b55f4ac91ef39fb7b9e7eb4aeb9aa9436ef7cf63fc2786ae3c6f97890c713ec72f2c5363cd8f086871b3c386692fe48ea67ddde278e0fb0c59b97c09330da10be70e1f7ed91ba37d30627883941bb471fc3bbd97c6107909f2bcb71a71871ac1097e4e465978b1e37cafd7ba6565cb76ee868cc73c03a5550c7cb04f28b2f250f00f52ff147e10aebda8d5122a7b2e4bfff04a8c93d8833a1abff0029b946559c960d2966b30e2be71cec71cacb81af626857253ed339fe7b0023e5d46aeac33b825b8fab791656c850bb1c98c980b2a61cbd7f75b65c7a67e99f7dc3e80e05ee73a1740ca91a7bf07262897b47da7e294c0f8709983e6bf0e6f0fcfbd8d7ac88b938c713304c3204372fef3b1e079c7be0065660225415ed79d86de7f780fa8ad1878dd59ce05c2d8f09cda6e9c1a53a1fce4e4bb30c3b62297d614fdd2c49109527ba7bbc70eead0643c5e7a2d3a324f593c9f26ee8f226852599f4a6d66752c096e2dfeb3bbcd4a9df463bc10fd4ab1c67b0b7d462f093146494c2f8aff5b987ffb408038c16dbf29589a28b17766c75471f994a023644f35c6c68237a237a4e26f39b9ce6fc6a7b7ab257e811b2238d05fd70cee312032ddaa288ff50508a7f14a1ede01b5b1a2bbc7bca5954e6b78ba0286729d06feba4d8b6b2f55bc483e7adb856efd82101fffeffc70218022354fd6dcd90faf960
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25997);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_name(english:"iTunes Version Detection (macOS)");
  script_summary(english:"Check the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"Apple iTunes is installed on the remote macOS or Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Apple iTunes, a popular media player, is installed on the remote macOS
or Mac OS X host.");
  script_set_attribute(attribute:"solution", value:
"Ensure the use of this application complies with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/07");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2007-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");
  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");

  vers = split(chomp(buf), sep:'.', keep:FALSE);

  register_install(
    app_name:"iTunes",
    vendor : 'Apple',
    product : 'iTunes',
    path:"/Applications",
    version:string(int(vers[0]), ".", int(vers[1]), ".", int(vers[2])),
    cpe:"cpe:/a:apple:itunes");
}

report_installs(app_name:"iTunes");
