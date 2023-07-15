#TRUSTED 072279b505bc48c0d08d47e16a7cf2847b5886548cbd1e09a6d6407845cfa87df734d9517d20fae9b5da06b3c3dc817a985bd04bb9d189efe16313d56aae72b7d87bf74609f75565aeaa6fa8474a89b9a15965d55270a39d43eb22cde0e7e8e599a53c4f5b456ed4a9db7d54fd0a84211fb4e25d15ec020656af17c492b0b48793b75c8176f326072f737bc637fe39324865e10d17562eab936511feabf5da4c27c47e93bd832ca77b520de1a58a33da8344aaaecf82eb490be801aff9a7aa84a1bf8b4e6dba1ebefad2f13767b0b18e1e8c6cceb945df7ac7fdc1be1c52093f10b2c814de57ed8f775c85225fd97842247095d07248bda70d79645b656a8b815a1456b84a3aa7bfdd92398711b89657fb93e6e7e298203162361971dfef2ed8174723aaf3a0f5be31cc696fbdea5d5799dafd6ce799be9325807e603ac6f47d9f528408fadcc7406eee71b4f02bba9e137c926423cbb7da0d1a767a2e7a1c462de2f7741ad46de7e05541a9c5215f479e2bc523fade3439802af5a1824f3ca784b536ae2584cf4217210ea167f08d35141f8045f571b4302a211e9804e23c27272d2121dacfde665d3f48a05d4cf54df2edf48b7d592cf5315111d0be2db349c425be010baf189f5b911bcbd94ee1db0b1715d2c81f460ce3f4a3567a71b7050e15b9b19acbbc8f207d445f0634f40d4c65e688071816707900c22990f0dc50
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59914);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2012-1894");
  script_bugtraq_id(54361);
  script_xref(name:"MSFT", value:"MS12-051");
  script_xref(name:"MSKB", value:"2721015");

  script_name(english:"MS12-051: Vulnerability in Microsoft Office for Mac Could Allow Elevation of Privilege (2721015) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by an
elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office for
Mac that is affected by a privilege escalation vulnerability in the
way that folder permissions are set in certain installations.  If an
attacker places a malicious executable in the Office 2011 folder and
lures a user into logging in and running that executable, he could
cause arbitrary code to be executed in the context of that user.

Note that this issue is primarily a risk on shared workstations, such
as in a library or an Internet cafe.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1894");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '14.2.3';
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
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

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
