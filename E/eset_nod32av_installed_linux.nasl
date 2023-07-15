#TRUSTED 485848b1e6b38ac7b1a64a299cbc2841472d8a0890ffc2613007448d9787d421746219a4fc9afabd806670a3b98465ecf980f62710aac60d8674ae4acf9c1c63932ecdc7d7177874b56bc547683ec7fc1c151caeabb6a88296f1066b783162634b0c5038d58a3b69b8cd4750c853292311986bc3c6e4d87e0f2568d350829e5c1fbc2d19f92b2e109d7d8ef1b478d8d25f61025484ca74ab167abc292cc598d09f34a7ab9a597006afdc3462ccc479574e84b64488269308c2ba1f408ac1ab6616a156409397808e774bd5caaa0b2d278fd316585b7be622576f3ec5080b254da4c44280eb06d94c17a464f452fb45b58d6b043883e49a602efe107e24140d87487f51d34adc81c38cc044ead0d904726c52186a7f4bc72feab99735f3831ed15342b9d4cc29c3ced98b6801a766d1733ab9cae9db479412d940fdb3c5d884484535778136a25fbb39e31450992668f590776520331ec921fa5e279662ff02237f87a29fe8088e3c6fbd38cd31bbf197dca1e7d131b1f1c3d465375667e8e4430d8862f81437155a6059a80c53d846d6d243bce68b2cbeff6abedcb26247be550a085f5e5c60079207777583291a5a37b351d72897643a99a57dd508948be45726c64667094547aefc7cfbc32660ba4edf77be378bb9cfa673a54e7efeb7d3a77a6c83e2d787aeddab075e747920e8ac2f68379a9ef1b463f5a8c3176a22d8b2
#TRUST-RSA-SHA256 8e47ed36f7b27df35703e711e1898172c720cbdd94c5f7e0b7be463864f4dc6035e4303926cb032c68b0a1fb64796d9abd4615f6aea36a0f897a60b88dbc477543fd95eaf78095db40a0b156ae9272067fd01930749c0ba1416df6539fd6b23e7bacb91682a41d5eeeecc6b7c6d87d30e16ba5dd8678ea1dd15f481a3f91273b52c84df9004f4f5ff1196c55f83c6d2698674beb70a9812bbb7b6ae17a0853c0de40cd9190ab11c3fb7377b43abd4be714fd90d922ab6623af525bf16abb6f3737b6a8c5a15cb4c366761ced19d43d4a6e54adde3e8b110965ae4874565b7760d227c8731b764c45be7375781fafe77be675368f249a7483c96b6ad77d6874eb15cccdf8e644f9c07aae77a625f844ea022ee426522a289ab493e90670e2dbd1ce8d16448ba0de348a9984cf48c09fc833c33939b97bff8f03e20e6e9faa4dbfc5ff5f97985e89f86997cc21976cc3576b8c46614641390b9fd89efa0f30f9ab4bfa9dfc7e5ee164ae7fb9c6c5ca0328b85e84031ca18390916a658436c156ac568f9c11990804e976e4b9b01e0cec6e6ffca6b51cfd41d2c4279cfd2bf1ee87a740b68cbd57d7171b09b3561de755cd522e6487bfe5580a9845873f97894eda31486721c58ea40206d500bbbc285656af6c897f63c1fe121bc2d924136206b12a152646c0273a601b43cd42a79f0a5fd2ec0f7a275153dc2fb57bcd71f9d44c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105255);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"ESET NOD32 Antivirus for Linux Installed");
  script_summary(english:"Gets ESET NOD32 Antivirus version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an antivirus installed.");
  script_set_attribute(attribute:"description", value:
"ESET NOD32 Antivirus for Linux is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.eset.com/us/home/antivirus-linux/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:eset:nod32_linux");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("telnet_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname")) audit(AUDIT_OS_NOT, "Linux");

app = "ESET NOD32 Antivirus for Linux";
version = UNKNOWN_VER;
virus_sig_ver = UNKNOWN_VER;

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

info_connect(exit_on_fail:TRUE);

# first get the program version
exe_path = '/opt/eset/esets/sbin/esets_scan';
cmd = "perl -pe 's/[^ -~]/\n/g' < " + exe_path + " | grep 'ESET Command-line scanner, version %s' -A2 | tail -1";
output = info_send_cmd(cmd:cmd);

if (empty_or_null(output))
{
  #Effectively nop on localhost (agent), so no need to check if ssh is used
  ssh_close_connection();
  audit(AUDIT_NOT_INST, app);
}

if (output =~ "^[0-9]+\.[0-9]+\.[0-9]+$")
{
  matches = pregmatch(pattern:"^([0-9]+\.[0-9]+\.[0-9]+)$", string:output);
  if (!isnull(matches) && !isnull(matches[1]))
    version = matches[1];
}
else
{
  ssh_close_connection();
  exit(1, 'Failed to get the version number from ' + exe_path + '.');
}

# then get the antivirus definition version
path = '/var/opt/eset/esets/lib/data/updfiles/nodA409.nup';
cmd = "perl -pe 's/[^ -~]/\n/g' < " + path + " | grep 'versionid='";
output = info_send_cmd(cmd:cmd);
ssh_close_connection();

if (output =~ "^versionid=[0-9]+$")
{
  matches = pregmatch(pattern:"^versionid=([0-9]+)$", string:output);
  if (!isnull(matches) && !isnull(matches[1]))
    virus_sig_ver = matches[1];
}

register_install(
  vendor:"ESET",
  product:"NOD32 Linux",
  app_name:app,
  path:exe_path,
  version:version,
  extra:make_array("Virus signature database", virus_sig_ver),
  cpe:"x-cpe:/a:eset:nod32_linux");

report_installs(app_name:app);
