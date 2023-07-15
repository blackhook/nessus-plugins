#TRUSTED 63e34fe7d2cdec795e34df32040b3ab54f7b986e9b99f1793cad678c7ca3d5218e2c0c0cbe020ca820e79e62ba4ecddc662682da69145a729c120165afa0770b6d14ce1d312b6b962a2dfd75fcd2c19cbdaca3248dd521003c80b48048e0e0bbbd796a557e6080ed268b5f7998d96f7cbe241a2421ea39a0f72533918cc0a45933aac9e9661c05d02943e14e2be7b9cec1cbdaf3ec5948d4eb1dd8df783c33b5de0ec0311407b533ee2a0b2ecb667d993d5d1cb6df3aefd98b753f04aa25a88a3b4a9cac050f829e6e289ff00cc19d892cb67d72372bcf0793acb11a5d808bd4800040024c9028202a10fd6b1ccbb2eb98e00bb868787529c3db068f0a6b1d9140bba3bb1594f48e26773fc8f5feccbbd39250b465f49cc0e7d6e5a40eded48b38fadfb57a951bf932ad3f639e6d3190030b09cc868ad8970d58f2d1ebb897bfc3b88f5a4f316f06d1a4f8830e03c36a26d82d0bc8cc052ee99159e6ff37d6c66dba79975a651e7f72fa89bd5e87713b30d9c9e291f010df25a60805f0430ee6679733c8ce226de62f4ec9d76b3e13699251f347d948f58887901d2465428c9b91be560a60e4b49823c6b914051733dbeed435de26d88e8d438abeb1a7e7135b1a9df48c2060e3dc6777ad7563f46f2bf7d224e4e10da070082d248568ba68c152a2688e9da4830eb5c68702d45e7945596c93ac028e9f6b2e223d20e547c682
#TRUST-RSA-SHA256 24e8f67cc1133ce6fb2e140955fcaa28310ae5d75cfaac76e4cde01e14a62a064dd0fc708f41aa41b5b2262aa98741f8e7d6b00463216863333be2d10eee70d3bfb7e7c5675686e6056807f05d9704c906558ab53eac1b3f234ee2bfaab470ec061cd16ae050d44a23b48a7e84e50d1d3839f30eb2373f7cf0d10e43b5f4264be8c12e0540dd2b36c732726fe061b639ff89ae325abcf3c8b02c555d71c5dd313b49e0dec88044c2a263447f2ff2b5b92125b76baa605c48e0d13120bc7fdad3a52d3deb96cae8d8970c5cd8c2172bb2ec85b79ef2910ff33fbf1c1e7deb857fa725ba57394bcdc28b9ec74254cffdff5fc29feca5d9881c0aac035100781ec2f3588b07d6f86ed4ef7b448552b57de01fdd4cfb84cb65e796868acfc9e6fcf19f34105f02bda7a661f3d4444de9c718130e12eac8bd4aa652d3f88eb53c88a5f91309ae7ad9e8c17f7d091aa90fb973587edee30df11542c182556a0887c8d08991e6cbcf81317165d1f70f1e947ea7ab8826b34342d7842cb5054e244f44bb0c63a1e8de55812638ffbbd7f12ae3c55d1d6688ebcc9cabc71f9abf122fcbf6fd75b10fcf2e2c8bec1b99e64ccd37f81a34d3c9780c70a3917413c45052092fac9c5f5f623a54286b9c2b55fede79ac5c340d4abcf4e00a14156f04e2e262a27cf20a3a34f10b9a5db702df84b1655892171f3b76f3f2434f679a910a26d8ac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69261);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_name(english:"Symantec Backup Exec Remote Agent for Linux and UNIX Servers (RALUS) Installed");
  script_summary(english:"Gets RALUS version from beremote");

  script_set_attribute(attribute:"synopsis", value:"The remote host contains a backup agent.");
  script_set_attribute(attribute:"description", value:
"Symantec Backup Exec Remote Agent for Linux and UNIX Servers (RALUS),
a backup agent for Linux and UNIX servers, is installed on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/products/data-backup-software");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("ssh_func.inc");
include("install_func.inc");
include('local_detection_nix.inc');

ldnix::init_plugin();

var app = 'Symantec Backup Exec RALUS';

var port = kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var ret = ssh_open_connection();
if (!ret) exit(1, 'ssh_open_connection() failed.');

var path = '/opt/VRTSralus/bin/beremote';
var cmd = "perl -pe 's/[^ -~]/\n/g' < " + path + ' | grep Version';
var version = ssh_cmd(cmd:cmd);

if (!version)
{
  # Older versions can be fingerprinted via agent.be
  path = '/etc/bkupexec/agent.be';
  cmd = "perl -pe 's/[^ -~]/\n/g' <" + path + ' | grep Version';
  version = ssh_cmd(cmd:cmd);
}
ssh_close_connection();
if (!version) audit(AUDIT_NOT_INST, app);

if ('VERITAS_Backup_Exec_File_Version=' >< version)
{
  version = strstr(version, 'VERITAS_Backup_Exec_File_Version=') - 'VERITAS_Backup_Exec_File_Version=';
  version = chomp(version);
}
else if ('Backup Exec -- Unix Agent' >< version)
{
  version = strstr(version, 'Backup Exec -- Unix Agent') - 'Backup Exec -- Unix Agent, Version ';
  version = chomp(version);
}
else exit(1, 'Failed to get the version number from ' + path + '.');

set_kb_item(name:"SSH/Symantec Backup Exec RALUS/Version", value:version);

register_install(
  app_name:app,
  vendor : 'Symantec',
  product : 'Veritas Backup Exec',
  path:path,
  version:version,
  cpe:"cpe:/a:symantec:veritas_backup_exec");

report_installs(app_name:app, port:port);
