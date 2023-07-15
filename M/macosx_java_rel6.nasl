#TRUSTED aa7c31cfd0e155763ea899614005522a21e4eb299b5f3f5d495bec4a8dc252cbefc01bbe2234ade44265dd8d22770af9521998f47ac3cd6d2f7c461d54ce33966a3e9522d68eb4eaab6c4fdb7cb84b0f928fd37c94304c4062751c66e3858b491c96839a10d73512ac85092246b510379ef588c6358ffdb3b0e02736c4a472b60336b841a916d26061182221d51faf40fe55d7f8612bf9e5bcb196612ab30a82e8e4281be9d96251b02d1b259a015d4521d62ad6784745d9466948fa9e173c40e2b34d5dcce2d725f0f5e8d19bd30995059c193551aa4496ac88b6d9c98e60ea8b7b157496a9693a79a239de06bd333f580bac9ab864a189f558555a2cf191c6a303f1d31982ab3af9117211b1c81f4d19e52d4b0900851d6ce8b30925bb1d3735947f9f3540418b78c56b6a063881795169cc3f7baf7748494c1ec4887f63a85726358dc9f60a24d57bd96f73a978d1a56da4bbc7419eafc28ba03d4bf7db1406f1157d73b1a8d0395a6c389b84e3ec4f6bc8ad3bb8fc786d8c4cd60aa6a24dafb28090ee1889f15fe5d76e29a5b18d8c0adabd4f560543989cbad179fc91d742a926fac95b4b3e37035f7d5be4608fe901ad17a70c4f48734d17eab0a1cd55b21880e7c2b3326abbd4470502f741774b956da53a9fb9771867616f567a601ec5b45b4cc2fc6f3d74b233b106e395167226561fb90d39432153705735dfee08
#TRUST-RSA-SHA256 1c1d6a466abc18b26e2e06baaa6bb37b3a7ac6a63dafd0bbe60c228fa6c2854fecc222945356519b7c71bb5c5279b44a45fa452b4579ac20f6bb159ff058708de53e99cdd93b47eed0e4b926836efc24a90a28a1e0672208ac756588a101a55bffa15361f6ab1d7080e50433368f37de00407fcbbf936883bc624cf1769726e2fa0924573cc51be6e2df067c52f26adb47d9e57d35d3848d29a6bbaca094238f24f5158caa8a3860fc0abe121c35269d8b5eb8839f951a12730b1861274b26b966ce79c26f2b9f491abb65b8b9ec3427f71175b9c06ccdc239553385b86da5c70cf38ab639499b6e697621ad4a9bf340ec57ac990ce8746b5567fb4a7c4ed1057300a4ea1a7b40967b9af8bf480bfc33d261f6fd4c0a80cd541232ca4f2f47c05c42476a50915574f1490d7bd296093b56a326b4cb0558dc9aef0f31e2cc184969fb5348719988198e61071c2bf35d431d4cce6bb3a30b5df5b62db991eb0bf7912a9b5f00c90b38ee46448e9fabb76a05884a2b3593fd0b3a396a77435be551f8c82e11536bb79edc83472b89b337e82fdc298115400eeb119ff06e38a6ade0244f47107380780f99f3decb7fab368751a4898ad92783c323549696ccc61dda164fb2e9fb8def26f9246742142c51a70afe92e66069a241d107e0ddb4f9863def9f20a1e2f1889aa34242575a56720dbdcfa964f6dfdb1dd8d7008d4947583d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29702);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id(
  "CVE-2006-4339",
  "CVE-2006-6731",
  "CVE-2006-6736",
  "CVE-2006-6745",
  "CVE-2007-0243",
  "CVE-2007-2435",
  "CVE-2007-2788",
  "CVE-2007-2789",
  "CVE-2007-3503",
  "CVE-2007-3504",
  "CVE-2007-3655",
  "CVE-2007-3698",
  "CVE-2007-3922",
  "CVE-2007-4381",
  "CVE-2007-5232",
  "CVE-2007-5862"
 );
 script_bugtraq_id(
  21673,
  21674,
  21675,
  22085,
  24690,
  24695,
  24832,
  24846,
  25054,
  25340,
  25918,
  26877
 );
 script_xref(name:"EDB-ID", value:"30284");

 script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 6");
 script_summary(english:"Check for Java Release 6");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.4 host is running a version of Java for Mac OS
X that is older than release 6.

The remote version of this software contains several security
vulnerabilities that may allow a rogue Java applet to escalate its
privileges and to add or remove arbitrary items from the user's
KeyChain.

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307177");
 script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.4 release 6.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-2435");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2023 Tenable Network Security, Inc.");
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
# Mac OS X 10.4.10, 10.4.11 only
if ( egrep(pattern:"Darwin.* 8\.(10|11)\.", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"CFBundleVersion");
 buf = exec(cmd:cmd);
 if ( ! strlen(buf) ) exit(0);
 array = split(buf, sep:'.', keep:FALSE);
 if ( int(array[0]) < 11 ||
     (int(array[0]) == 11 && int(array[1]) <= 7 ) )
 {
  cmd = _GetBundleVersionCmd(file:"JavaPluginCocoa.bundle", path:"/Library/Internet Plug-Ins", label:"SourceVersion");
  buf = exec(cmd:cmd);
  if ( strlen(buf) && int(buf) < 1120000 ) security_hole(0);
 }
}
