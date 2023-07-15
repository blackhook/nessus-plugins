#TRUSTED 9f63ef003b31789b97878f1091ba75578c5afa9ed2b9ff2d17e093f0aeaf9f1236ad782e4540fe0159e78d3fccaa2f97982927b87006c91f60b8dfd5f1a8147690fbefa2956d75851eb08cc3d22b61fa04fa614de1dd8ea18dc94f363be2b02aaac66c5184c03ed7197dfaf8109bc11b99c6ef6144103d8a735291ec696b47a3f3cea2c2711033e69f9c4905cad4db8374b06cbd05d66b689ef1af6cf0b6ce23286ddad1a91bb48ef1c8c38d4198430a8ede4c16ec3d93685fb64fe9f4a3c97f57873db0341cae1e968ea19d1b48a49b04e5cc12602d1d3bde79412a6fd557f22d557e5a587a3926d05cf53023c151c4686fe80a9789df044ff53bca4e23b9e68e0a9652216ee06f022f4dc289cb9fb0c0835581afbd3ea3217aa0c753be7e7c65ca47e13ecccf0c6b9ca8b1d6286016c24c28e6d46d891c35f0586d0b160229ac08628c4f2e5b33ff9c6fc1a7e9d704fd69fc75011e3ff8201eeb29a231e419f7c9faabafcbc5b83852369980e7c74a2dc26dd7ae960a8408d0a481dab85f364baf58f3b45c339ca4fd3e6a7c2ebca4b49af497b720ca92c8c718193a4200bad95f4649cd5b3395975da052c4bb40a4ee8ba00d102ace7271ad737b5e4259bd014e961f3df51910999c3aaadb36c4c046118c9021d5fd0897191590ae4ed249bafbccc43b8f33fbbdec2dc5c0e6897653d152120dc6efc212a7911806ad505b
#TRUST-RSA-SHA256 6dac1a4fafb0d6041b425a1a6ee60edc4fc23742e3783b7908438e6ccd79ef1e52f70bacebc8e142b36b4976c350375f81927736ba1f49eeafaf4599282b8ab0f2147f4a15ffe24cb8aa6071f151d4bbb249aad509700721ef36150a060e5f657f31df2c336a5bafe700498a976725914f4ca096614d4e6a5a4989afd84bbd4d3549a22a19403d429dac3c74e8eb4538d4d756a75dfc32065b98b419ee9f49fefc496f92b45ebc3aa2aafc328aab35df8092f18a7657ff6c2a9bfe7ed62eeafcc27ab3134886bb542b748a26c1f0df020cf6536031489bfd58ef34c23eaa3b01add307c4a3e2a07b15a4e100666bbb129ca41daca315de28e1adca19faba29a694368ef84535fbadc07bb5d591755b4abe615e8e735737662467e31283cc72cdc974f110e06913e4f978761f65f7242030052aeda2dea1334d0a440cc20bd860b62a9ecd5dec17a0b327ea26ae1283155b6494115253bc24fd6c11b9969af247ac22aa75f7e334ebdc9c220b83e58303ba220fb979df9e6456b6a4e36a8608adb8b1fd8be69e74b6b1be37566092910c48dd6ec522eb15b86670cd810acdfd2b44ff57c368b08a97d50c1d8704d811ba4d20c04e200d40862e4d60893991a5437dd04ced3b7dbdf72eb5322b6017b1f4cb3252ecd69d6b82003d5c5b7e43a029d1a9607fcf4d1aecbee2a1b8d8b2b920617e2b1aa85189c38549db3726cefa6b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34291);
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

 script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 7");
 script_summary(english:"Check for Java Release 7 on Mac OS X 10.4");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS X
that is older than release 7.

The remote version of this software contains several security
vulnerabilities which may allow a rogue java applet to execute arbitrary
code on the remote host.

To exploit these flaws, an attacker would need to lure an attacker into
executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3178");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Sep/msg00008.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 7 or later.");
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
# Mac OS X 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.11\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 # Fixed in version 11.8.0
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) < 8 ) )
 {
   security_hole(0);
 }
}
