#TRUSTED 498620475cb782dc974088b10de13426a611f31b6b979d5b2953e76ff85037626262439d6febb6e549883cce7b5e6c0ca82e5b2bee6f739b09a63875985c43f5ec619551aa548c4313431b7f88d0c5cf0ff16515710e7540b5e363ded4a38004a533d32d2b3d98cd7ad0f243b9201f6c93234e0204110c2261cab9c7b05ce143ddc1c93c984396efadd0052e500e59fe2dc734219cfeebd5a7704ba1a9d2936f1cd4c62a370115dfb4d162f8066b540d9d8881896bccac3d5bf1c4f71afa5ecedaedeb59826de3d018f6698f64f57726450cdd968b34b2a067ebb2fd3b4ad8d12af4a7dc610759d2d203ebc95e2102cb995b4da11b6e39b5ba2f31e79f01c8b0d968acea32c94d93dfb0a22a61e55a51868a3a5da8dd0d18049f36f664efc97480d9da3ccbe11bbd55ce6d0329f3e078ebe1df05a7929bbe2ec9597b4c7abdd4b3203ce65d2ad06d1d2441fe6db840a132038638ed83e3c22f7be532aafab256c38b4b3a5120f09ef3f126c4b3b38fd63b8cd74ea84525a2dc781b110c3b475285928887162a0af94ebdbd1e2f3db22cd9bc4c3cb668c46cbae5adcac2562fd44fd4fd997a3eb9cba7cb2e741c9f168e7cc1e64e088e0541b1a696c9e813016705c073bf59fd6f602f879e48bd6ab849a4842bc90cc97cafb03580236b015cb8bc67976b939b2504e047853cd1271b83e957e26888dda9a3cd0903f952077984
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78436);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2014-4117");
  script_bugtraq_id(70360);
  script_xref(name:"MSFT", value:"MS14-061");
  script_xref(name:"MSKB", value:"3004865");

  script_name(english:"MS14-061: Vulnerability in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (3000434)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by a remote code execution vulnerability due to a flaw in
parsing Word documents. This vulnerability can be triggered by
tricking a user into opening a specially crafted Word document.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-061");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.5';
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
