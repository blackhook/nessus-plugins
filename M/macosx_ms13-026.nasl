#TRUSTED a5cfc35867834c8b62043648c69ebbeaa2b16d817f9645afdaec5a273402661030c1a4d16d4ce1e7d94d22180ba0171ac8e676e7116de48a969d49044e5791debecf4c14c266446da8ca16567b9e749550262663c3e19072e6918485390cc35fd4d6ed7a6d717b35314f29ed7ed74593aef954ab790b91145dba255b0869be3eda79c66c9cfe2ac5ed1df350ea744c836bb8239ec7fcaab2ca57e4aca684b56888e05ef5477005b6b4a661d75417c06e13a36a9dc850ee9c031696300435636eb54e0c96080c1f52331a6e347efef53dffbaaa8c89a4fb23e5ddfd714c447f85e1a494a426ea60cbde62c19468b2398ca3f554a06e9e44c9e2ff9cd58c148015283ac9850d83558365fe9912915ca81060e57110996f834e4e78235137988eeb437e28103c03a7f8d24c5221154147e0d13167f928949c2523d854f0e2fce8fd9164fc97e77addb6eb4fc7524ba872e8fba08f6e398bd58f02fd8ace47d030c92a25e652fb8a6372a04f8286ef5a2ba4c924f823ae80b51c225c1092ad7ac7f1535b66e468f5879b9802552e7e363ae9ab0b65c8af41bc2eb7ebc0d64c9ceea33202e6b1f89a7577eb2c07c6393c6bac8d42a6bdbcd3501ba4ec6a0f035329a1fcdd955f993d4fb54962972e710cf97a55ada96b69d0b19386ade8d33760f15919fe1f9ddc9453e0c0d8598e8070700b4110c2e1441d2124416ecdaea682b4ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65217);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-0095");
  script_bugtraq_id(58333);
  script_xref(name:"MSFT", value:"MS13-026");
  script_xref(name:"MSKB", value:"2817449");
  script_xref(name:"MSKB", value:"2817452");

  script_name(english:"MS13-026: Vulnerability in Office Outlook for Mac Could Allow Information Disclosure (2813682) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Outlook
that allows content from a remote server to be loaded without user
interaction when a user previews or opens a specially crafted HTML
email message.  This could allow an attacker to verify that an account
is actively used and that the email had been viewed.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-026");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and Office 2008
for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.3.2';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '12.3.6';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
