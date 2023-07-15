#TRUSTED a539cf18af954a91175abe68c05f2da9468060c4c4d468812008f4bd530ce4fcb33d62078d752e33ae216e61d255c3a69efcaeec1122890013f2d9ce79ab639ca3cb33c0e8b97d1ad5d22ef274d5a9caa66230eb45d0625dcf32096e31508bcb47c80cae4386babed3ee4e941d8b4cc2dfc736f51a6123b87a82e2bd69e4f12f52c18af15afecf36b5297c2370332381eac45062d44aa21b0ac8f3bb614dc42ea706f83bb26db5f359846db39476bf127103f35badcc86caf346bffcec6fae13d3afd313939a31f0e5f6ffbe7c6a00b1deb0fd58ce663b128d0fe04ed743c1c0809b31950fc7f5dfe5da1cefc21403a7a7b44c093f48f2f45a7249004f7562ffabd49e846341b87f70f49445782e45a22648e95245633bbd7fcf9155087f65712900ed8c73b3090b2eb32c4c13ee8705ef0c761e6d704e12d36bc5f5740542cb9815074036583d2e8935e994ac0485b16647cc2111c164a472603c542943b420b0e08dfe4e732ff3ccdc74c4a74863d54a7b0c185a63991b853dd12036063f166b30f1466774d84f01337705e1721ff22636d6b1c073a3b1914eda828128584b38df87ba1928429853cf22a6d7f7a74b94514c478f23e7830f4e7df0c3bebe6354477a68de36a055db8eb2cac210540b025e6330dd58073d41947633339be53ecc97f2b2d85c123b4784485253bb6d5f8652110fe2adb696837bd671d54693b3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104498);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_bugtraq_id(101664);

  script_xref(name:"IAVB", value:"2017-B-0150-S");

  script_name(english:"Splunk Non-root Configuration Local Privilege Escalation");
  script_summary(english:"Checks the Splunk configuration.");


  script_set_attribute(attribute:"synopsis", value:
"Checks Splunk configuration on the host for a local privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Splunk install detected on the remote host is vulnerable to a non-root
configuration local privilege escalation vulnerability. Please refer the vendor
advisory for remediation actions.");

  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP3M");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate configuration changes listed in the vendor
advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score was calculated by vendor.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
servs = get_kb_list_or_exit("Host/Listeners/*");
uname = get_kb_item_or_exit("Host/uname");
process = '';
splunk_home = '';
running_user = '';
conf_owner = '';
etc_owner = '';
vulnerable = FALSE;

# This plugin only works on AIX and Linux
if ('Linux' >!< uname && 'AIX' >!< uname)
  exit(0, "The Splunk local privilege escalation check is not supported on the
remote OS at this time.");

# Find splunk service
foreach serv (servs)
{
  if (serv =~ '/splunkd')
  {
    process = serv;
    break;
  }
}

if (empty_or_null(process))
{
  exit(0, "The Splunk process was not detected on the remote host.");
}

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

# get path
match = pregmatch(pattern:"^(.+)/[^/]+$", string:process);

if (!isnull(match) && !isnull(match[1]))
{
  splunk_home = match[1] - "/bin";
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the Splunk home directory.");
}

# determine the running user
buf = info_send_cmd(cmd:"ps aux | grep -e '" + process + "' | grep -v 'grep'");
match = pregmatch(pattern:'^(.+?)\\s.*$', string:buf);

if (!isnull(match) && !isnull(match[1]))
{
  if('root' >!< match[1])
    running_user = match[1];
  else
  {
    if (info_t == INFO_SSH) ssh_close_connection();
    audit(AUDIT_OS_CONF_NOT_VULN, "Splunk");
  }
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the Splunk user.");
}

# determine the owner of $SPLUNK_HOME
buf = info_send_cmd(cmd:"ls -ld " + splunk_home + " | awk '{ print $3 }'");
if (!isnull(buf))
{
  home_owner = strip(buf);
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the owner of $SPLUNK_HOME.");
}

# determine the owner of $SPLUNK_HOME/etc
buf = info_send_cmd(cmd:"ls -ld " + splunk_home + "/etc | awk '{ print $3 }'");
if (!isnull(buf))
{
  etc_owner = strip(buf);
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "Unable to determine the owner of $SPLUNK_HOME/etc.");
}

# check running user vs owners of etc and home. only a configuration where
#  they are all the same is considered potentially vulnerable by the advisory
if (running_user != home_owner || running_user != etc_owner)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_OS_CONF_NOT_VULN, "Splunk");
}
else
{
  if ('Linux' >< uname)
  {
    buf = info_send_cmd(cmd:"cat /etc/rc.d/init.d/splunk | grep -E '^[^#]*splunk enable boot-start'");
    buf2 = info_send_cmd(cmd:"cat " + splunk_home + "/etc/splunk-launch.conf | grep -F 'SPLUNK_OS_USER='");
    #possible mitigation
    buf3 = info_send_cmd(cmd:"cat /etc/rc.d/init.d/splunk | grep -F 'su - '");
    if ((!isnull(buf) || !isnull(buf2)) && isnull(buf3))
    {
      vulnerable = TRUE;
    }
  }
  else if ('AIX' >< uname)
  {
    buf = info_send_cmd(cmd:"cat " + splunk_home + "/etc/splunk-launch.conf | grep -F 'SPLUNK_OS_USER='");
    if (!isnull(buf))
    {
      vulnerable = TRUE;
    }
  }
}
if (vulnerable)
{
  report =
    'The current configuration of the host running Splunk was found to be' +
    '\nvulnerable to a local privilege escalation vulnerability.';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_OS_CONF_NOT_VULN, "Splunk");
}


