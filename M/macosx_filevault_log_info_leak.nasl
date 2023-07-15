#TRUSTED 1b9438a57c82abf5fabdbb6367c9f33fb2b954a04f543e291834b7a4dfbe73df1deab2a52908bc654c94b900092fef827ca3eae63772c7ce168a40dd88ef6b9877c5f30cdd88fee1e788c7151c1c5399358a9bc8a643fcfeeadd152e3425369e7f104dd971536e317f605f727bb011a02a554dc7750e631edfdff73b55615f2595d41d615bcec6465ed997b43cf39d51e4ba20c511395f948433680041c637f00ed55309e49664325ab84c83d731607aeb32ac7b2fd7eab62cb42be46ee65d0927a89bec1839db92d0e45246df8f55c092786bdec5118e32da56de74440421c8ea404303ef5a5308fdad323b48092b0112e9b425dfb91df701765287f5575e53dbc251cb10ea53941b95064d6855fdd3b68ecc2b6b9609942537667874d2d562878432c71028fa0064894647ca805a2b36d1636a0694e9790a223e63e7adb970a09e33b18aeaae72009611148556932137b040bf2a8af5fa7455dd0d37e69810e954e09422c79123218dc8c2a93b20068523dd9cd5202b11d741f149beffe3b02b95be6f7a8b5ebd9a0fcdc2a84cb5acd15015612c162caaad92d7d5dfabfd9575a5ce076c3b64d0802c4a6a01afce63980b83e2e167f0aaf105a71004da9824dd682a2eb97a05a25421c735fcf45a1ede102c0021a87edb60a3fd1eb3fd84827f17f3448ecbefbdcc2d30266df0cf001d80cf30840f1f104d91db8cfcf68681
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(59090);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2012-0652");
  script_bugtraq_id(53402);

  script_name(english:"Mac OS X FileVault Plaintext Password Logging");
  script_summary(english:"Checks secure.log files for plaintext passwords");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Mac OS X host logs passwords in plaintext."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Plaintext passwords were discovered in a system log file.  Mac OS X
Lion release 10.7.3 enabled a debug logging feature that causes
plaintext passwords to be logged to /var/log/secure.log on systems
that use certain FileVault configurations.  A local attacker in the
admin group or an attacker with physical access to the host could
exploit this to get user passwords, which could be used to gain access
to encrypted partitions."
  );
  script_set_attribute(attribute:"see_also",value:"https://discussions.apple.com/thread/3715366");
  script_set_attribute(attribute:"see_also",value:"https://discussions.apple.com/thread/3872437");
  script_set_attribute(attribute:"see_also",value:"http://cryptome.org/2012/05/apple-filevault-hole.htm");
  script_set_attribute(attribute:"see_also",value:"http://support.apple.com/kb/HT5281");
  script_set_attribute(attribute:"see_also",value:"http://support.apple.com/kb/TS4272");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Mac OS X 10.7.4 or later and securely remove log files
that contain plaintext passwords (refer to article TS4272)."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/02/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");
ver = get_kb_item_or_exit("Host/MacOSX/Version");

match = eregmatch(string:ver, pattern:'([0-9.]+)');
ver = match[1];

# the vulnerability was introduced in 10.7.3
if (ver_compare(ver:ver, fix:'10.7.3', strict:FALSE) < 0)
  audit(AUDIT_HOST_NOT, 'Mac OS X >= 10.7.3');

cmd = "/usr/bin/bzgrep ': DEBUGLOG |.*, password[^ ]* =' /var/log/secure.log* 2> /dev/null";
output = exec_cmd(cmd:cmd);
if (!strlen(output))
  audit(AUDIT_HOST_NOT, 'affected');

credentials = make_array();

foreach line (split(output, sep:'\n', keep:FALSE))
{
  # this might be asking for trouble because it's unclear how the logger handles things like passwords with ', '
  # in them. at worst, all that should happen is the last character of the password will be reported incorrectly
  logdata = strstr(line, ' | about to call ');
  fields = split(logdata, sep:', ', keep:FALSE);
  user = NULL;
  pass = NULL;

  foreach field (fields)
  {
    usermatch = eregmatch(string:field, pattern:'name = (.+)');
    if (isnull(usermatch))
      usermatch = eregmatch(string:field, pattern:'= /Users/([^/]+)');
    if (!isnull(usermatch))
      user = usermatch[1];

    passmatch = eregmatch(string:field, pattern:'password(AsUTF8String)? = (.+)');
    if (!isnull(passmatch))
    {
      pass = passmatch[2];
      pass = pass[0] + '******' + pass[strlen(pass) - 1];
    }
  }

  if (!isnull(user) && !isnull(pass))
    credentials[user] = pass;
}

if (max_index(keys(credentials)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

report =
  '\nNessus discovered plaintext passwords by running the following command :\n\n' +
  cmd + '\n' +
  '\nThe following usernames and passwords were extracted (note' +
  '\nthat any passwords displayed have been partially obfuscated) :\n';

foreach user (sort(keys(credentials)))
{
  report +=
    '\n  Username : ' + user +
    '\n  Password : ' + credentials[user] + '\n';
}

security_note(port:0, extra:report);

