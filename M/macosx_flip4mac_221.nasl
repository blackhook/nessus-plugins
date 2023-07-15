#TRUSTED 3ef09f738cecf40cd9c7ed79672a4e70e058ac710255fa555524c0eea3397fb306ed48375743fc2a82f694e132e8a2698f76854ddfff4fd50dee979782e328bdba50096370fed2c95af4d7fe95ad3af5bfe3a288e3b46c7f6c7bfd327570bbd6b98690190fdebe9ab2f418ee54441579777ab30a43396fc1636fce6ca3ae0f1e99472c4e11802c15836468e1813fcdcc59c5d05cfb11d0828043ee0b41d5e33f072108bed79edf2d3368f5094c3b7aababddb8a5dc8bddc1f78aad001336b8769caeea5560458e59fe4cb359142a04585c8b8a1fb2cd0c7d99f3bd6c92a5e1bad95ad369604f4371c0af2f597c6f83d4895b45ee69ae5a0494e2ffbf0121e92ebf850c4f43c22d57c80bd397085acb8cc55e0693c0064a1cfd2ea4b600640a3117b5fe1daad5b2e6d16e369dd93943b65ffab3975a0fed33edce84445a1f1a535c6317bfff8152c043ac36f0525194376d648045048a035900d17a5fca492b4396560860b98edc9c0242177b4ae3ed088fdbcfc572609a238da1ec551a388c9968b90c6b32a2fce3e1fabe348fe7e0780de255113c2a9176b441afad502b03770cd08fa1767bb428ab8e402d383ef96c9d6476180d15540d4dfbce8d1d96749331069377da2a5657aa744a2b67c16d5d4e04a2f7fc427af80bc0addd02562252015e3e60416d76c55c22bc298cbce8c6ab315b2ceb5ab48afc053d3069211b8d
#TRUST-RSA-SHA256 3107ae138403ed03357a30dd5bd7aed32ce647858a159a7536905c972d024801e402e6eafd9f8e80f34d921539c091ac86e10e7aaa15cb59a828d49bb8b162660a1acecafdf8ed3387366b2dde35656f8f58d0be4effe91e70182529ce1fc8bd123c90526ff6c88310427bce3c46cda08a87c10f31337cb23022abcd70277a4c8248e72506295928f3fc7aa01184de9b66aa2bf0c5b2633f3749c0caf7e7443db2cbace989abeed57c405b712ba87d1ba3ae6ce79ebd47441797fd7a312ddde4c081543c8cc58d02ea779efbbe5671a72024e20bf107987ec7af1f56331eb59dac79024841cce703431bcc1891e2e31c8ccb34aa2301db68c39c5b5ca8fe53462f79e7f278fc2015fe4c6909f8ff4fec5bb1528bc6f522633952ed45e9d8334a7550d35a9e3c5080dd27f9f3d9c6d6599cddafbff5b9abefae66cb4c554ad4c7ef1e4d0c9509abc7cdf22f68dfba97c6b71250334262aebf2ff06f5b36724080a102455b21ee4211ed01116fa5a5d18be7db237ff0380ed91e76d29c34778e5f6a7fc42e57ce1a66aebad8f07219bde24650e98d55ef0ed2038ec2a93c50c440b209c9be798c8f3210281635c1e74b7d129a94aacc7a0b12b62c0937723fd0df4f9e3ddefeb0902c756129ebd6ee621942fca0d8087ae4b11dfbc2d68e9b7389b7dd5e339974f0e382c6b02d792cdc2f270d8020ea48b42018e24db7d3f783c6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34322);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2008-4095");
 script_bugtraq_id(31505);

 script_name(english:"Mac OS X : Flip4Mac < 2.2.1 Unspecified Vulnerability");
 script_summary(english:"Check for Flip4Mac on the remote host");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a vulnerability in its WMV decoder.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Flip4Mac that contains
an unspecified vulnerability in its decoder. 

Flip4Mac is an extension that lets users read '.wmv' movie files.  By
enticing a user on the remote host to read a malformed '.wmv' file, an
attacker may be able to execute arbitrary commands on the remote
system.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1935549");
 script_set_attribute(attribute:"solution", value:"Upgrade to Flip4Mac Version 2.2.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-4095");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/01");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2023 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

if ( ! defined_func("bn_random") ) exit(0);

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

function _GetBundleVersionCmdInfo(file, path, label )
{
  local_var ret, suffix;
  local_var cmd;

   suffix = "/Contents/Info.plist";
   cmd    = "cat";


 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && ";
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
;
 return ret;
}


function exec(cmd)
{
 local_var ret, buf;

 if ( islocalhost() )
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
 else
 {
  ret = ssh_open_connection();
  if ( ! ret ) exit(0);
  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
 }

 if ( buf !~ "^[0-9]" ) exit(0);

 buf = chomp(buf);
 return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* ", string:uname) )
{
 cmd = _GetBundleVersionCmdInfo(file:"Flip4Mac WMV Import.component", path:"/Library/QuickTime", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 2.2.1.11
 if ( int(array[0]) < 2 ||
     (int(array[0]) == 2 && int(array[1]) < 2 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) < 1 ) ||
     (int(array[0]) == 2 && int(array[1]) == 2 && int(array[2]) == 1 && int(array[3]) < 11 ) )
 {
   security_hole(0);
 }
}
