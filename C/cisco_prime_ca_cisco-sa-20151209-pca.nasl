#TRUSTED 610562ef8b4e66b39f3289cacfd32f082364a2de50fccd9298c1518185eef421e8fdc585695954ca93ac04c6f37397f991ad9122410be48d2aef6928e29b05a4e86b51822f1e5d75f6c7dc78b27f6426553a84f56593449328534e31bab3a2f99cc5a12b8407ea3e1df62272e6a858e03f118ff13f27ed7da38d2248ff8bc3b14e5912b5f899a74cff56514040b89822bf02dfc7371be6e2288022c22456f237c84d33238ffbc9f7eb42656e2dfe4024fe40d036a8575716742906b4d8a5c6c60f122293edbabb69557e40863f730d9f01a2a18318b05e4517b9da6d736786a4d9908af944e26eef2eefe2a18588938a83c8ade34306aff6d5c7d52304312146b4906a06282cea2e9bc8c8cbcebd41350f12408c3e224d688f965b5d67dec6ca4a3721fd9d3571e5be1660f372b534b4f78a36a7ec0facb7754da05cf62eb5a41f0f1e98158add4d08725ee1ba3cf5783a7d005b707c4d0835f0b082c9196409865309b5689b9b5041bc3e1556799a6c9cb20abbcbbb1bd8adbb39d362eafde3efef1382cc7a20036100199637ec6427ad14151d4f72b65a23450e3be2ef6f3c6e2e78b15d9f184fdd43168cda249cc5c4c41e5c356d15ca46e8959b651253bad702875f07b63fa9d9257de2067bf20b4ede9c26bd7123d24ca50480566f64390a5831dd0b5b6cea89d7732370c970d10c23952f719130f82670c0b3c9096637
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87506);
  script_version("1.20");

  script_cve_id("CVE-2015-6389");
  script_bugtraq_id(78738);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus62707");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151209-pca");

  script_name(english:"Cisco Prime Collaboration Assurance Default 'cmuser' Credentials (cisco-sa-20151209-pca)");
  script_summary(english:"Checks the Cisco Prime Collaboration Assurance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is protected by default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Prime Collaboration Assurance device is protected by
default credentials. This is due to an undocumented account that is
created during installation. A remote attacker can exploit this to log
in to the system shell with the default 'cmuser' user account, and
access the shell with a limited set of permissions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-pca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28fa8c84");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus62707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Assurance version 11.0 or later.

Alternatively, a workaround is to change the default password for the
'cmuser' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_assurance");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_assurance_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationAssurance/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

checking_default_account_dont_report = TRUE;

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

appname = "Prime Collaboration Assurance";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationAssurance/version");

login    = "cmuser"; # default
password = "cmuser"; # default
flag  = 0;
port  = 0;
extra = '';
report_extra = '';

# Normal version check first
# Affected : < 11.0 per vendor
if (ver_compare(ver:version, fix:"11.0.0",  strict:FALSE) < 0)
  flag++;

# Check the workaround (are default creds gone?).
if (report_paranoia < 2 && flag)
{
  # Do not try this if the user has specified
  # that only user-supplied credentials are okay.
  if (supplied_logins_only)
    audit(AUDIT_SUPPLIED_LOGINS_ONLY);

  # Setup SSH bits
  port = kb_ssh_transport();
  if (!get_port_state(port))
    audit(AUDIT_PORT_CLOSED, port);

  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket)
    audit(AUDIT_SOCK_FAIL, port);

  # Attempt the login with default credentials.
  login_result = ssh_login(login:login, password:password);

  # If login fails just keep port at '0' for
  # the version-check reporting.
  if (login_result != 0)
  {
    ssh_close_connection();
    port = 0;
    flag = 0;
  }
  # If login successful, attempt to run 'id'
  else
  {
    ssh_cmd_output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
    ssh_close_connection();

    if (
      ssh_cmd_output &&
      'uid' >< ssh_cmd_output
    )
    {
      # Login okay; 'id' command okay
      report_extra =
        '\n  After authenticating, Nessus executed the "id" command ' +
        '\n  which returned :' +
        '\n' +
        '\n' +
        chomp(ssh_cmd_output) +
        '\n';
    }
    else
    {
      # Login okay; BUT perhaps account is
      # administratively required to change
      # password before running commands. Or
      # any number of other mechanisms that
      # complete the login process but do not
      # allow 'id' command.
      report_extra =
      '\n  After authenticating, Nessus attempted to execute the "id" ' +
      '\n  command, but the attempt was not successful. This could ' +
      '\n  be due to the account being administratively required to ' +
      '\n  change password at login; however, the account is indeed enabled ' +
      '\n  and accessible with the default password.';
    }
  }
}

if (port || flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.0' +
      '\n';
    if (report_paranoia == 2)
      report_extra +=
        '\n  Note that Nessus has not attempted to login as the "cmuser" due' +
        '\n  this scan being configured as Paranoid.' +
        '\n';
    security_hole(port:port, extra:report + report_extra);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
