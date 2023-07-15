#TRUSTED 326874a42fc359dc453a0952f018378092348e450a831217301caff661fb888ea27af3de0a8c372362388668ad54c01a5cbab6ad8796ba8f9f24581ae9c5905b1e191ae4cf3ea1bb15ba2903fffa78bcb6434a75dcba0c92ea0dc753dfc2b1b03533510e8cbcfb2103c69a5a9cbfbf542c6de3b160b02db49ef568e913dcc1f7ec8b9cf2165d8f3b981a68e507787a72705bd6c56db0a2334221ce3561bbc677434c3ea8386f42a08cffade79afc5bdcedbe8e88b69dff0f1056e0c34fbd75ccd11604a9315f7d97adce166464cd1231f5f0aca87853796123a7ac01c55e610782c516da8667fc692d2cda45038e6c50b9d26bc5907f23841d5c55d2cc8be8aa85083a2ae4c09d9cac3416562d9d181b24a93cef5fb0869a81975b10c1510a0466d8b2e426c0bbf85e3fec649de6eb700664cda08937cfac21ee5deb5c481e0b8fce43b36e5c4550f0c649efd30ceee06fb10cc90b560059fb881aad33eb8297dc06680b551ce0e3f49e658e7c7238587e33bfddd795266fe371a85115295d62e8d093888d000831e9d3bb1f8152a675b4eff490871405b28e1c8584302315c4f1f5bfc3d6645a93be8d103a7deca0a058aa2aaf10fcb5ed0b0596a7e9a085ea3e9e372007358b55026649448c4499d9593dcae85f8e43df0af1cb51416d36e48f24c43fe37073e9eb530c6b4907762fb6d6f505a0af373a4e605230aaf9fb4c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69514);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2012-0397");
  script_bugtraq_id(52315);
  script_xref(name:"IAVB", value:"2012-B-0027");

  script_name(english:"RSA SecurID Software Token Converter Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote Linux host has an application that may be affected by a
buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"RSA SecurID Software Token Converter prior to version 2.6.1 is
affected by an overflow condition. A boundary error occurs when
handling XML-formatted '.sdtid' file strings. By convincing a user to
run the converter with a crafted file, an attacker can execute
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2012/Mar/att-16/esa-2012-013.txt");
  script_set_attribute(attribute:"solution", value:
"Update to version 2.6.1 or higher.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0397");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:securid_software_token_converter");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("sh_commands_find.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

fixed_ver = "2.6.1";
grep_template = "sed 's/\x00/ /g' '%%%' | egrep -oa -- '-(android|iphone) -o -p -v [0-9]+\.[0-9]+(+\.[0-9]+)? \%s'";

ret = ssh_open_connection();
if (ret == 0)
  audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());

info_t = INFO_SSH;
sock_g = ret;

find_args = make_list('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin');
if (thorough_tests)
{
  find_args = make_list(find_args, '/root', '/home');
}

find_args = make_list(find_args, '-xautofs', '-tenb_fstype_exclusions', '-tenb_path_exclusions', '-maxdepth', '4', '-type', 'f', '-name', 'TokenConverter*');

find_output = sh_commands::find(args:find_args, timeout:60);

if (find_output[0] == sh_commands::CMD_OK)
{
  find_output = find_output[1];
}
else if (find_output[0] == sh_commands::CMD_TIMEOUT)
{
  exit(1, 'Find command timed out.');
}
else
{
  exit(1, find_output[1]);
}

audit_report = 'Fixed version is ' + fixed_ver + '.\n';
vuln_report = "";
vulnerable = FALSE;
instances_found = 0;

filenames = make_list();
if (!isnull(find_output))
  filenames = split(find_output, sep:'\n');

foreach filename (filenames)
{
  # Remove newline
  filename = chomp(filename);

  # Skip blank lines
  if (filename == "")
    continue;

  # Skip filenames that don't match a strict whitelist of characters.
  # We are putting untrusted input (directory names) into a command that
  # is run as root.
  if (filename =~ "[^a-zA-Z0-9/_-]")
    continue;

  grep_cmd = str_replace(find:"%%%", replace:filename, string:grep_template);
  grep_output = ssh_cmd(cmd:grep_cmd, nosh:TRUE, nosudo:FALSE);
  if (isnull(grep_output))
    continue;

  if (grep_output !~ "-o -p -v")
  {
    audit_report += filename + ' does not look like a TokenConverter executable.\n';
    continue;
  }

  # This could fail if grep on the remote host doesn't operate like we expect
  matches = pregmatch(pattern:"-v ([0-9]+\.[0-9]+(\.[0-9]+)?) ", string:grep_output);
  if (isnull(matches) || isnull(matches[1]))
    continue;

  instances_found++;
  ver = matches[1];

  if (ver_compare(ver:ver, fix:fixed_ver, strict:FALSE) != -1)
  {
    audit_report += filename + ' is version ' + ver + '.\n';
    continue;
  }

  vulnerable = TRUE;
  vuln_report += '\n  Path          : ' + filename +
                 '\n  Version       : ' + ver +
                 '\n  Fixed version : ' + fixed_ver +
                 '\n';
}
ssh_close_connection();

not_found_report = "RSA SecurID Software Token Converter does not appear to be installed.";

if (!thorough_tests)
{
  not_found_report +=
    " Note that Nessus only looked in common locations (/bin, /sbin, etc.) for
    the software. If you would like Nessus to check home directories in addition
    to the common locations, please enable the 'Perform thorough tests'
    setting and re-scan.";
}

if (instances_found == 0)
  exit(0, not_found_report);

if (!vulnerable)
  exit(0, audit_report);

security_hole(port:kb_ssh_transport(), extra:vuln_report);
