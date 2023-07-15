#TRUSTED 43a4a9ceeadd66ba518c4e9ffae94021da7fc2e93fbc20f8c9250519d4421978c73fa256721830c09d48b6e1be918b7215bc046b6fd43df8eb6ea795294f66c3cf019d9015b21aaa2983637be23cb946e42700ac3e0509120311affb812019d20e87e6746727d6ee336e9a1e948b23021db2bd552f7973b89dfa187449e3e59ee2e91c333fd973e4da2c733fafd1eb84811185caea2dca9da725549fa4d7e0ea1a4ebf524b7db9726212f853d2baa755cc89ffa5cb67731eaac1d3bb666dc3c44a1d3dde506e5e5a76116ca37319cddc83325e587e29f372cf226deaa3ee0adedf84793a037cdec384911a1616f0cf32bcab8a65052aa42199302f83f504e35c8a24f6c3eb33745a63fde38a83b538faf80362ec9cf3480cbbb1fbc12710aeabfc98a4168609c1c0e2f37a72cf3f04dc00d15da16eed33ea6766d70b57b73443c8a5de0d3187cdcc98eb15fee60ad1d9c3ad8b6b22e91800c2d82184817d727eb41284da67461a720349ee8c1e471b164e64a94e24eba32cf801407a114516408973d1302a765ed0aeff5b92447d655d3878e6900f7116c7c21b993c8a105bcc6577fdc56bcac960b1476208d1682a4abc239b1e5e181ad8ce2e36090fe7c768d46054f24835e36f4f1383fdcfe76842a2f581ee71e02033656a713d386f985754a74acc3b15672d1cd3c7cb32064ff862ed458868d900f4d92b8e36c9386633
#TRUST-RSA-SHA256 0aeb981621ea6eede7c16730518a6a637e20250abd0c473899fc1d71cb03f8b01789d1b67c8f2612634356a0dbd3abc1f10d4c02a714ee6c6c481ca1b2cd822af639766e53d628620f5a12be52bcc7243773bd82c78e85562c68833f832931303bc5ab1af9aeb17d3f7d397f8906ef8b97a51f76a0fdfbc433d212467cfcb62c6f094133c2439ba3f9c9b660666582754a042f3508ea90a305554597a0b5a954eaba384f1e2a0096353998c85ad8e3a759290e8a9bf0ec36fe119b3c774dbce507b77767c57402ba3a14804a1b24f0d6d35939bae954871c3f1784a307346535f650d28f9906f5599b8f5a1ea10ad30de4622d845f36cd8441ff2ccce0c26b6c36db5cbc3e84fc87c3e25f97260a19254b91c8af8d82166423d42deed875bfe38777227a1fabe1c819f61d7948e9b9599490ecef62b6fb4feb80bebfdd610b609f97bac69c0d4c6d7118d655fd42f228cff2572abfd30b3752696619029ddf1698298ccfbd222fae4e340ba4163e1088235f8ecf14c4da150cf68defb89e0159fb2f3253824dec22d81ab848b7ff77039fae5d520175ab6410feb47319d74ec714fbee64811ae396bb2a8576f2a7270b6180f6a60b7573e555a15cd02a6b123fb40d08b8472190c3a18cb1b6540442f80b37f3d6ae64d576e0c46aaab599ba081c6b33dde806f7f1b5b627ea270e62803d72d62a90ce2ecd915beb836a41a5d3
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(50073);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-1826",
    "CVE-2010-1827"
  );
  script_bugtraq_id(36935, 40235, 44277, 44279);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 3");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 3.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
or applications to obtain elevated privileges and lead to execution of
arbitrary code with the privileges of the current user outside the
Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Oct/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1321");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = 
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.3.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 3)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 13.3.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
