#TRUSTED a1d7a992cde04575c1d1cc39b9ae70b4533e82dcedb26f3aad06af9ade2ed8090d168951988a418acf9af97f2a988fabfc4c40da1394147631b0c10b947cdba1e47a09597a92e918f76f0e2c0bcf887f100ce67234e9db33a67f0a0c437df3bb74b7b42f331397bf88c8535e3806a7472ad826d81c115877b239bd21e50c92095eb56f5df05292305f2cb7ec2b3cdfae4972cdbcdf7eae2880a87b39c48ca5e7c60885635dfddfa2d5deffaf66842bb4d0914f1a81836dbeb2fb2431aecc1235dd2f2820910e866e53f47de5324a9c1b43eb8a78058454db108b0e3dc135c39dd906e1f80514f8634ba0c2198b119f14ccbd4d987f8510e36506827c48677283204c6dd49a72b54172eb8a46aba04fceda68c92d0f6b7751156fc190d336150349f592401d37217b95bd418ba4cb56ea9b996af9377f88ba76f93468d10f44b02d3ca1f7785887edd1a1c4c7010b00c2329d4f8fdda1824401782f5be7aaf65d41392eaccef753fef7f77a68b6546bbda9af529359f869d1c146bc5b7abf8963f488676ed07f2cc4fd75064075056315616558b57929307181b7b88c177deb11c9bb59a3da77c1082d782c4aa669bc5a2447fa790c9fc0687656c646b14ea06c0b61f4acbb36883b3301fc736c3852177b0adfe137bc8167d01c5c4b643eeddd08c9f67162ca11bed2ad6bf54b33b744b92257f845ae6fb9d80972c5729ee55d
#TRUST-RSA-SHA256 873a16793549ad80877e8cabfd7dbd593796f139a234ee8394d145183680de71bc58912d8a2407a4a8c5cab8d6da720562711e171e9c109ea45e3499f14ba9e0d1e073101f01532f77a2960a3c4ea89f4ccda111349d2fcabaaec716c58776197b04c43279336c7713fdfda41e8d1058578b0ef1b0e59bf2e46ac4854729a8468f87b6f184b1419cc23ed9cd2cf5da54f0571615a129bd378365b559477c66b051b4c1500da5dd0ca5824a226660877db970ee373727d4e8bde38773310fec195c692beceda10bbe8e629433fa4e7b4979d0e158b59b1908dca307530c891ce12115cfae0910efbd31340e46b6f24026b6cd23c56a1a650304c58de85abe0f54281139ac7e2591512b320ddf3eff710a4602baabe84ac4bfc39843f68ab9200ede9db7e3fcf697753ae5dae4eadbff02d51d92a737eff6068dfceecdc549882e6d4273c22a0674b61a03fd4637d47e5610c0ce5a3254fb27f10e000da159562580da9d1ca26d677d6db6b15f933e6919703485c4466b058267018968a2951f7e593639659c841a349b14e61edb851d7aebb915ddb3355436066eec15b4f285180f05bc4ad2b3409719d172e0b934dae77ca9fc483640f9e3b2d2e3b1dde3886d3e5122349dbae2d7e36c24ce416c9b03edc0d6fde38f4d30cc09c4868cf2c5ddf680eeacd4b72756c8a7e21c8e5157e91747aa853b1c6b2e2c9f6164a03fc661
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69788);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Cisco Network Admission Control (NAC) Version");
  script_summary(english:"Obtains the version of the remote NAC");

  script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the NAC version of the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Cisco Network Admission Control (NAC) Manager.

It is possible to read the NAC version by connecting to the switch using
SSH.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:network_admission_control_manager_and_server_system_software");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

##
# Saves the provided NAC version number in the KB, generates plugin output,
# and exits.
#
# @anonparam ver NAC version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, source)
{
  local_var report;

  set_kb_item(name:"Host/Cisco/NAC/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/NAC", value:TRUE);

  register_install(
    vendor:"Cisco",
    product:"Network Admission Control Manager & Server System Software",
    app_name:model,
    path:'/',
    version:ver,
    cpe:"cpe:/a:cisco:network_admission_control_manager_and_server_system_software"
  );

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
# setup ssh tunnel
uname = get_kb_item_or_exit("Host/uname");
if ( "Linux" >!< uname ) exit(1, "The remote OS is not Linux-based");

sock_g = ssh_open_connection();
if (! sock_g) exit(1, "ssh_open_connection() failed.");
# issue command
nac_ssh = ssh_cmd(cmd:"cat /perfigo/build");
ssh_close_connection();

if (
  "Clean Access Manager" >< nac_ssh ||
  "Clean Access Server" >< nac_ssh ||
  "Network Admission Control" >< nac_ssh
)
{
  version = pregmatch(string:nac_ssh, pattern:"VERSION=([0-9][0-9.]+)");

  if (!isnull(version))
  {
    report_and_exit(ver:version[1], source:'SSH');
    # never reached
  }
}
exit(0, 'The Cisco NAC version is not available (the remote host may not be Cisco NAC).');
