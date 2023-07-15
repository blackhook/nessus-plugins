#TRUSTED 38a0d7f113d8bc2f3099c991cc4b15515675296820c16182e52a72c0e85f2e2e1cc8701d706119a9b8839da4cb46fe52b1dc13a1aa3e7516623d5fa8a430b78bd6d82915311c197c762845406120c73a2d948d503865e74c958801ff750ac0687cc70cbb20fe095afd7dd7e458424649396ab9fba964cdee97868d57fc0e77e2641e3a0214552e420b7370d02ecaeb1c444f0dda71295e5ce423635702d6539ae3fce892b884310eb706424f0f305e8aa48d7c3af3d23b18017806df47587aa260689704d0151e04cacd0a76a92aa3c2709d0b0c8e401e5d136865ea23dee6f1af67f52ff62686f4790d06bf80c711ae0b26edfa7cfd10c1f7be1d0a1a4387dfa8a5b063c19b2218c518f18ad1ad07484dd4597f8ae506d2b30a16f31b49f62aee8770a398b913eae3c0de60cbf3e313e8f5f60a785c70362252374d6df6abfa8e0759e6f04a1274b2adbe577056f698335e12201de95ba0193051e372885ccf009bfb221bc428ff7efbc1d7459e78b33e1255f5670d379e060ae13beebee2ec5bf250560cfa045a4345016c0403e350ed2b38ea0f9036c67d08e5669a4f268c11819a6deb39c7954318bc68069ba09015199b433e104c2fffec3ff4784d92875c6bf6dbd3d9bd8f0d70ed79d7cc6c5f88a0f717c48fb2567be7e15e992870481582be479f560e49bd3c447121f17fbc86c3b5f37e0bf094171845403bf26092
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(66868);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-1331");
  script_bugtraq_id(60408);
  script_xref(name:"MSFT", value:"MS13-051");
  script_xref(name:"MSKB", value:"2817421");
  script_xref(name:"MSKB", value:"2848689");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"MS13-051: Vulnerability in Microsoft Office Could Allow Remote Code Execution (2839571) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office for Mac that
contains a buffer overflow vulnerability because certain Microsoft
Office components for processing PNG files do not properly handle memory
allocation.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, this issue could be leveraged to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1331");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

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

  fixed_version = '14.3.5';
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
