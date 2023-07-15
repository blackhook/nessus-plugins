#TRUSTED 8f37ca3574d043b1b63392d53b3296916965191ecb074ec5947d0976b052cff0b84025450bfc4aa7444b347522c0ac169f945f82f8b29131db0c65da638eb0b023355adc53fcbdf7578f5fc7646e42380dd9121904dfcf3e88c6c5aad8b7821097c27c5d495c87e58e7926800b04f47e2ba1988ad09407cd9578d0d411d8283a19f12cfbc734ede87bc3bfbfe8359b9db9aedff3ef189edfbafa28742bb0a29e0e2779cc681d124d358d5e1b86e076cbf9bed193a08cb8a81a02d15367a6917f4ec1c5ec8283339ba60d11e5654e7b58312e7110cb7d9682578b19525231f74ca9f441ada6c024988136953ba20c05d37d1045ea09dba323f1e7f5d3403ceeed5914081dc30b9abdf8e67e8c27b2c02fcb6c11cba1341da45b97e88486ec78abd9a0d2f2bb8a453b3806ec7fea083c5d806f4f70991c27529477c31ebe2b9184ec04fe8404f3a953e9b0954b23affc9da6704ab0c98dd5315e276ebc3774284a044233eeed292d7b60e274f3b42de5e7055cfca5ab9139c1aa6605da6b702a00fd3b2b0ed81f3bdef644b9b50c0b7866f467e620d4d035d81407be2d194c3f51c067891991f0527ed7c39de694a0225dce3b697c219ed4cd5ce38a2f2c9dc215dafa1f4195256abdada1cc094ac93f67ad94be91fed26b50d39dd171e90a282ee7aff79a046970af8ccfba0ed781ead4d4bb74c7cc5f8e7d4ee17e1e681ce734
#TRUST-RSA-SHA256 98ee92927c4a9d56d539e68c5eb40da1a93de2ac823cab7cfa2dbcc01b9bf840cf5211e49e2cc6168523bec922029b68365d08fd5f6a4bf171f317e7477f9bb1b15c6e4f943cca373bd6dbe9e14c62106989094f8379ede0f7caa3b3658b21b34261d7c6be9649a3546a7c8d18fd1db083fa508f5e8a22f87060a641bb3def2d8ace737e396b8951b124ae0001e2216454f85922b569192a14594e2f5a580fe588408356c18e290d8ebffdf25fe11f4b80baec43c6f370287afe549d3d551920af3e41ba574bcec4be3ed17552021e77e71ee48f39326c3feb16c4abd2d6d8d5c92c7b4fd7ae8f053437dc2044c549078919a9857ee3b410672cdc7aded652afff993378c25aab3008c5f2805aea16f4a5bf3edbe26147627cdfc4c2b3b71e8dab741f69d7abf09bf624b9e51bed4ab9b9e5a2d69883239db9bc43107df0f4d2f32643425f8387a3459ac7d40e10fddc5eef935a95d915e72029de28745d171d680c5b41290707069d1ef786b9ffbbeaa4c863afc2f150e520933e8557fffb81ed1411dbf2e1ec6d08c561d80642a8f102da4cf5c2cc0355cfb33de5b0536c185674521d66711c3bd73536ee51f069d1129681fa432c3738377c6d8bb79cdd151d0002427f0f8af4d3a5a5f20cdae7818bf685ad4cd794aec154198a41ce3cd7cc4beacf5f369e03b6acae3bf083e3678e12bf104ce31989b7d955cd39678006
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(34290);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id(
  "CVE-2008-1185",
  "CVE-2008-1186",
  "CVE-2008-1187",
  "CVE-2008-1188",
  "CVE-2008-1189",
  "CVE-2008-1190",
  "CVE-2008-1191",
  "CVE-2008-1192",
  "CVE-2008-1193",
  "CVE-2008-1194",
  "CVE-2008-1195",
  "CVE-2008-1196",
  "CVE-2008-3103",
  "CVE-2008-3104",
  "CVE-2008-3105",
  "CVE-2008-3106",
  "CVE-2008-3107",
  "CVE-2008-3108",
  "CVE-2008-3109",
  "CVE-2008-3110",
  "CVE-2008-3111",
  "CVE-2008-3112",
  "CVE-2008-3113",
  "CVE-2008-3114",
  "CVE-2008-3115",
  "CVE-2008-3637",
  "CVE-2008-3638"
 );
 script_bugtraq_id(28125, 30144, 30146, 31379, 31380);

 script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 2");
 script_summary(english:"Check for Java Update 2 on Mac OS X 10.5");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.5 host is running a version of Java for Mac OS X
that is missing update 2.

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to execute arbitrary
code on the remote host.

To exploit these flaws, an attacker would need to lure an attacker into
executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3179");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00007.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 update 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3113");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(264);

 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/25");

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
# Mac OS X 10.5 only
if ( egrep(pattern:"Darwin.* 9\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 12.2.0
 if ( int(array[0]) < 12 ||
     (int(array[0]) == 12 && int(array[1]) < 2 ) )
 {
   security_hole(0);
 }
}
