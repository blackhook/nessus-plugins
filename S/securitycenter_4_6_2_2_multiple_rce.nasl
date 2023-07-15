#TRUSTED 7d8a2d0191e0af9ca35356bc03e1c3776cdcce5ada725f3447251d3a7aa2c5bea425176f723b81c120b2a645757c9b5479acd0ac8d2c38b8fa7b0e4c9becf0acf1ff84f7e65e368743e20f867b9f88ee4ed1b3f94236896067aef38df89c9ec3f2c82b15aae77e15d934e42a59b1c7ef2db2d18511579c8958e4afefb610aef8852af022b1c1c0c5f86e29ff2f059b32fddde3f620f4a6eb6ac08e47d253544d06385dd94e6d89b8e6e634527a74c604817d73dbec1b75561a4c8ec4874289c79743ae63ffcfd40ec48b030c65d3e328c49490f0fc3e4e2d6bf696fff0a17019844ff3effc8c91ce42203b1e2e6bda8bd570679883c0e25fff42d039d5dabd9d529596636972d072b813596a30995a75d8c0fdeeaf4fcba84472b438f2addc4908644532a99cd9f4bc0baa5b83759310f53bfaaaff3d29def0945b50425bcdea9f76d8e9f30bd51e37ca1a308175f2fadf0b17a71bceb95c66f63482312e405254e1b61bb9bd7f482dfc809113c9678579cdde1843b2005440a69201c1c805fa4da38c39b07ec8a452eafce13f82082c0dac3969158de37f70d2b636fe0bd7d83a55901e9aa2e0020675257ddb23f7a444d86694023cedf9e5e7e829a549d723b568f8a8a91ef204cf4b93da12e0ff580ed5e0f7b6c0cff24954044541c02c30bbe825a23222353a9c0058094da6873bce525d708b77bb6032bdceef9d83c344
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85183);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-4149", "CVE-2015-4150");

  script_name(english:"Tenable SecurityCenter < 5.0.1 Multiple RCE (TNS-2015-10)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by multiple remote code execution
vulnerabilities :

  - A flaw exists due to improper sanitization of
    user-supplied files during upload functions. An
    authenticated, remote attacker can exploit this, by
    uploading a dashboard for another user, to execute
    arbitrary code when the server processes the file.

  - A flaw exists due to improper sanitization of
    user-supplied files during upload functions. An
    authenticated, remote attacker can exploit this, by
    uploading a custom plugin or custom passive plugin with
    a specially crafted archive file name, to execute
    arbitrary code when the server processes the file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 4.6.2.2 / 4.7.1 / 4.8.2 and
apply the appropriate patch referenced in the vendor advisory.
Alternatively, upgrade to version 5.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Affects versions 4.6.2.2, 4.7.0, 4.7.1, 4.8.0, 4.8.1, 4.8.2 and 5.0.0
if (version =~ "^4\.(6\.2\.2|7\.[01]|8\.[0-2])$")
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

  file = "/opt/sc4/src/tools/customPluginUpload.php";
  # Patched MD5 for /opt/sc4/src/tools/customPluginUpload.php
  if (version =~ "^4\.6") fix_md5 = '65bc765ae62d8127c012ec286cabc686'; 
  if (version =~ "^4\.7") fix_md5 = '65bc765ae62d8127c012ec286cabc686';
  if (version =~ "^4\.8") fix_md5 = '5784a4f1e87ab0feb32f82a4dfd84c9b';

  # Check version
  res = info_send_cmd(cmd:"md5sum " + file);
  if (info_t == INFO_SSH) ssh_close_connection();

  if (! res) exit(1, "The command 'md5sum "+file+"' failed.");

  if (res !~ '^[a-f0-9]{32}')
    exit(1, "Unable to obtain an MD5 hash for '"+file+"'.");

  if (fix_md5 >!< res)
  {
    vuln = TRUE;
    # 4.6.2.2
    if (version == "4.6.2.2")
      fix = "Apply the 4.6.2.2 patch referenced in the TNS-2015-10 advisory.";
    # 4.7.x
    if (version =~ "^4\.7")
    {
      if (version == "4.7.1")
        fix = "Apply the 4.7.1 patch referenced in the TNS-2015-10 advisory.";
      else
        fix = "Upgrade to version 4.7.1 and apply the 4.7.1 patch referenced in the TNS-2015-10 advisory.";
    }
    # 4.8.x
    if (version =~ "^4\.8")
    {
      if (version == "4.8.2")
        fix = "Apply the 4.8.2 patch referenced in the TNS-2015-10 advisory.";
      else
        fix = "Upgrade to version 4.8.2 and apply the 4.8.2 patch referenced in the TNS-2015-10 advisory.";
    }
  }
}
else if (version =~ "^5\.")
{

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 5 && ver[1] == 0 && ver[2] < 1)
  {
    vuln = TRUE;
    fix = "5.0.1";
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
