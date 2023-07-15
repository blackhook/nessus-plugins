#TRUSTED 7f3d27a766fc384200ddcace05dbf461a4baecffa8df66813f32736cfc1b3b986a60f555c2b778552cb7a6ef023160822934b1f003e14feaa1026a526c9edf182aef3bae3512f018a7ea2f2529af3e6fe5609fe6573c2994a7ff59178bc96389ff5085d0a75e6a987130082e07a01e6f9c2c306a192686996bbe482705d307ade7cd6901e1addbe70e8d57916ae2509e60786c2a186557c11a7cdaf1c3f80929d3764b2191b509aad5e7bc283b24290b10ef362be867b6352f86b71daa6bea26bba10f74b396f01b7c77eb385a07b3e7ab24321057bdec1af7aaa585158da15daf58d328a38133592598f421fecbb782ff041d30a9825fa2b62eee4333aaba6bb53729c894d0ae09d96c549a65d6108147aaacd9269afec2657b382ba60b62ad6110a7c995aba6c1c4ebc45aa2fea7d0ee99f0d01de2783116f33d9c898302a51d1175f061e7c8781edd8caece3378463efd183062e0e88effefc704eec716036afc1dfe02e62e0e2e777224eba344b667db8675e4f5b6ea25952b28d1b2d332b18f47a8fd9e2f2483a227f7332f4d792b34f1d2c83ce57e17edc52de348db29d125ac14f540494f1a7dd7ed06666167447cdef22e1fb867589f82fe661e157648205bbcb75eb2652d567e39e4729b1e91742917315e9c89a7e41201680fa9a4c5eeb90ed8472a0b531b17f2cf55f825fcf5287db5de35774bb7710bce56dfd1
#TRUST-RSA-SHA256 437d64413b925228dd538e6a69946f2dd77ea79075e9f1892dd905945ab615af1c1cfda7ab9a38420beac8968bfa3b743f1042b966963043b13a371b42d37a017b7bc8be5ace60c86d3e74c5a344d940e56a6214ac6e65ec871a22073cb9f94aa6ced8571fc78e473268a3b3ad00995fe00dc473d85b32bfed9133d4590c16211bb4d45a76ea6eddae189191c5649106a759b497d2701585f62610517abc1486676074ea275e5990fad55046137d6e19ff0343306e0a161549b36e2a61c2e3a89a2070ff1e71dbffe6eb0adfd86b908691e921359c686bbefd9cc435318bd928d0d318d93a128baafd74b2f8ad2fdf02489c70d619aee568055737185f54869f1a3749f9b29adb92820cc25618af2eaf7161e48a066b70d6476d7a1561d8ce1365eeeb03c564d9d5cbcee1f90cde8f2171f94f86308a7fd843dc2520eabe5f7d19e8d0ea4dbce7e33ab7bf1361dea110fd72f3ef72163c58cc4664f2e669aa975fe7a09e12bb544fa1609d66f89450e2b9896974e05c4791b272dbbb56989d5540e86a842af9b49bee693f6a8be6ba2259376f3d0c6760644abc9b5360257192eed734112cb2e23d238eef8d394de2ebd5e31b69b05b69dd63bfadf45ccad93ae54bf1b00f681508cfd76649a2af7518b11bdb4f9766407777d041de8c5d74db7b6a8e6468c214817da06eb8335e67c9fdc25df1a5a1525daed9abee231156a1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43003);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-2843",
    "CVE-2009-3728",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3877",
    "CVE-2009-3884"
  );
  script_bugtraq_id(36881, 37206);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 1");
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
10.6 that is missing Update 1.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Dec/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18434"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3874");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


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
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.1.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 1)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.1.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
