#TRUSTED a90df940388a5a30b0d1da55f8a3e2e685475f089cd876ced6febc10d9420f1a54333ca9fc115db1976d14967f83b87bb579e891d38df70c228f11551af8a06c0ece9479963ee71c0e55fa33241dff5c2433a1d2e0ae37240196f1a35030d35de999d6eea789d276fcfda016bb425437993130b1d7870caa90f46a2e5a859dec0138b846f33148964a35b2c85432c98b91100a2b3f93a84b8600c4627fd5ddfa3378299ff10aa6fab96591956d549abb9e030c2cf4268586a689913b8dc81d119bfcbfad7cbb69156d1bfbdcd0ef397403124d05264f4d5cf1037e294a3a2b8fcb77dff08c16e82bdbce272199d0fc292c43e21c94ff47e03692ce2792bd32b1665f91857305148cdd3a905f0ebf6475bb1fe27db1baa100c8aa5ae55e1c14f114cd6f2653cc90544fafaadf8ed8e9eb8a5b995f637a7eebb8d96293b08646cfaf73cd0e1a05380188817020e273ccd72fbfcf74b2612cf291c417d74aad427c33f46916fdb194e0ba2d3a36e4d65b6238b6f9b87a42a1a967f408865a75b72e626a0d7a345d4aa59e8169384c7269614da6726d2dda7f8e2f8b6683299a79cafbfd8a1684ff31fb39a24f81dd476cd6cd98a46dcb094d4fbc93591a748193c0f5032644199c8f6c29de007610febe04cd2936627c0ce3938e283bc2694556d803e1bd3c328bef75bde678dbf501cb7f1785f08e0ba5b10f2e1e332515ab4a11
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70340);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-3889", "CVE-2013-3890");
  script_bugtraq_id(62824, 62829);
  script_xref(name:"MSFT", value:"MS13-085");
  script_xref(name:"MSKB", value:"2889496");

  script_name(english:"MS13-085: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2885080) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by two memory corruption vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-085");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

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
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


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

  fixed_version = '14.3.8';
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


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
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
