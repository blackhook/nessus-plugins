#TRUSTED 907366b7341b3f3cc575dbb51e40e52e6acc307d57905e9843087a8059c270420d82a083e1d0fac916ddc9e3c893a67418d27dd9236222fe258f640b6978deb74f3af8deb22484cbdfc75bdce62351f78d3e26639e9474885d5c4aeb3216e26193480b045e73456c52350aa0485e85d7e3f775396bbcea085035f4b9ac088ec75701aed74d63c51167bfb6353c3ca35934f4a4e0f60b93ef3ffe7c3f4c51b404b41546f8c3e5aab0387dfa6a51b25cdf11a1537cf89f15210aaf9e6906bd716e9a850138cf9b4beafd9b2c3c6e2be9394955e5ccaa519db31123b86343628b7335cd89ac27476c48c565f13648ab402cde799d996a53243d605afaaf3fb45000a637f7d5cebbd8a028279f18b2c60cd8c31bcad21726677fbe75ed8168c9e0312844d359b6ecfb366ae1214113e09b4ab05361be69927fec64e80f4adc1192edbcd26abd81314c5482d31cc9eb0134c8847351971920808ccaeaf9d40effa080ef2056d1de953ddb307f3b18bf1c6baab42ca9822a544dad444c64d8fe6939517b641a54bf287690b8d28ecad300d16b2feec8245d8a1a55a0d43a476c6d4ddbb5f38caf13a28a812ec845c2e04e02d5decaa646307aa1ca5d3249e709750999aea7f90361f15b1f35dee3338fd57f805b7a663773c625238b9eeaf20e0aa3cc57a24bd828b90dc8aaaa4e6d29db2619f5cd9118762efbe1a623ca5c9a774b4b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80194);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2014-3412");
  script_bugtraq_id(67454);

  script_name(english:"Juniper Junos Space < 13.3R1.8 Arbitrary Command Execution (JSA10626)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 13.3R1.8. It is, therefore, affected by a remote
command execution vulnerability that exists when the firewall is
disabled. This could allow a remote attacker to execute arbitrary
commands with root privileges.

Note that the firewall is enabled by default on Junos Space.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10626");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 13.3R1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Junos_Space/version", "Host/Junos_Space/release");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("junos.inc");
include("misc_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Junos_Space/release");
if (isnull(release) || "Junos Space" >!< release) audit(AUDIT_OS_NOT, "Juniper Junos Space");

ver = get_kb_item_or_exit('Host/Junos_Space/version');
if(_junos_space_ver_compare(ver:ver, fix:'13.3R1.8') >= 0)
  exit(0, 'Junos Space ' + ver + ' is not affected.');

if(report_paranoia < 2)
{
  if ( islocalhost() )
  {
    if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) exit(1, "ssh_open_connection() failed.");
    info_t = INFO_SSH;
  }

  cmd = 'service iptables status';
  buf = info_send_cmd(cmd:cmd);

  ssh_close_connection();

  if ("Firewall is not running" >< buf)
    security_report_v4(port:0, extra:get_report(ver:ver, fix:'13.3R1.8'), severity:SECURITY_HOLE);
  else if ("Table: filter" >< buf)
    exit(0, "The firewall is enabled on the remote host.");
  else
    exit(1, "Failed to determine whether the firewall is enabled on the remote host.");
}
else
{
  security_report_v4(port:0, extra:get_report(ver:ver, fix:'13.3R1.8'), severity:SECURITY_HOLE);
}

