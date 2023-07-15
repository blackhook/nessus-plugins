#TRUSTED 0a54d81128a64cc681d42cdd707db4135c23e2af9870759dee3f4dc6fa5d6ea9e8564d13a093d017bf40727a5d20ba45d722a13541e9d3a4fc77e2f9da78b48627e6e378ca909df95f51e8df0089e2a8d86013b6ba7b0ac30757027307228304a6746c8f44efd3bf8498891f5b40bbe8f3ce3a1d8eb34cabd7e7595a22bb18108b51a906c82253e1ae23cd16bf49f579e0ea22aab2336d053921af0b9f7bed93ecdea7ab1a030dc561debda04f273641cd9ec63905708671cfa0b7d71d3323ddfd6a756a6b9acf2828a2d87fef8d5e078022b4c58f8d86e1e4a404aa86153b3b2899714d9b46cb9e43bc6b9986ed83dc8dfcc670a7cdb10bff4cb132a45c2ded5e006a52890afd308e6dbb9d4c9174ce3f584c147413b1ce84f234ee5c9c90e2d8154215af5ed515b04a603b604612638f5fba5642d469b72e3cf3d52d4edc5161053736d08204a92a5eba0905597b653f0495706d0d7ffeebeb4d0f7291094199ce2dd7e94412e4b270e986adac02e0125b7b5296d01fc832fd029ac15aadb423b8406fc2ff4063e99d330051683a8d812fb864e8c0651cd5a74477268e7d29b84ce8998d5c73aa377f7e653aefadb849fa7e97e7a62461533788df61894aa9a61057560555c9e72977b79dd29cf8b91c4c2f2eb5d7e1e599276b6291f61f949642e70bdb824fffdf6cc23db81aea11db5117fbef83f760dc8b2e4da6da6d95
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97575);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");


  script_name(english:"Tenable SecurityCenter 5.4.x <= 5.4.3 PHP Object Deserialization Remote File Deletion (TNS-2017-05)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a PHP
object deserialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by a PHP object deserialization
vulnerability in the PluginParser.php script. An authenticated, remote
attacker can exploit this, by uploading a specially crafted PHP
object, to delete arbitrary files on the remote host.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-05");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:'cvss_score_rationale', value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");
include("install_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
vuln = FALSE;

# Affects versions 5.4.0 - 5.4.3
if (version =~ "^5\.4\.[0-3]$")
{
  # Establish running of local commands
  if ( islocalhost() )
  {
    if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
    info_t = INFO_SSH;
  }

  # Check version
  res = info_send_cmd(cmd:"cat /opt/sc/src/lib/PluginParser.php");
  if (info_t == INFO_SSH) ssh_close_connection();

  if (! res || "class PluginParser" >!< res) exit(1, "The command 'cat /opt/sc/src/lib/PluginParser.php' failed.");

  if ('$errorText = "Possible exploit attempt intercepted' >!< res)
  {
    vuln = TRUE;
    fix = "Apply the patch referenced in the TNS-2017-05 advisory.";
  }
}

if (vuln)
{
  report =
    '\n  Installed version  : ' + version +
    '\n  Fixed version      : ' + fix + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
