#TRUSTED a844776fcbbdcf8a9b8c447d46fe719f8a08d4eba0d927e477660542fc67ebd942ed2d5ea9008c84828a35749ede9c0f17e81dd42b514d60ed9880a6db7bef0fa8b59ee0275b8d15bb83af1753bb0f9eb7e9d769ec0248b21e72c75a9eefb3b0c98d64d23ef5abd60446e1485938ffb2b9dbc6a7beab5af645fe002816ccf9fc156b15cd3f0186a738b053c092ff8569a133e7f79cd2139c170ab5497fb84f6a9f7890a227ed450be9fe9867d40a9927a5c2b1cbc20f709d23c28b67f6be05e66a5542a6fde7f22f9e21220795bdd54b65a13dae1982d33a7b35e99ffa7d3e80465e9040276a499e7ab9758e7baf589a70efc22019b5ebd11f6e8fe747cc44454155c21f54c5d8e2df96f7051f2292dae4e4b084b4e5674b155d15a908171c15f1e2ccf7b38b7ff78debfb5a0ad787fa1dd5866792ca4719e8bd685094b7c9bb6fbc53e7782751efc2447d4afa59f23d8e6b0ecba13e25631a32dcb73274e87923db50999e03f2daee7f3a090003b5a79eb0648ca7eee51379c50f9c3f0d875dfb47ce59ba90cf3ca144dbeec455f9caaa3a65bbab6173e9be49f4cbf5ce85ce68f364399cb9f34747b87f7487caac6674c4b166d550590021f8ec29eeb4a06ae4317f94082ab0c12066a1621fa9c54199ddd532c2e86bb773bd55301424d89c58c25300f3bcd7cb1262cced5e274456eb54c2fcb82cace2e56001b34b9946e7
#TRUST-RSA-SHA256 584053f89f7b6a7c13ee6f6fb54c16880b1533167ef19b769bdd0cc4544c5f0d0f5c442ef97f061cce4e3baefb7e0457cbe18393bf2bc1c55e5a60c4aa462dbf2288b7d3835f58bc1872a8567cbb57ecd15cf3b27d60fdfe83df1dd83fd88f367876e83b7a3ab98ad07485bc4afdc8baa7c70f0404c40b95341ef603b6115b406b58cefe56ffa78a8bb08525416739e1ec67d40e563726250d0b397e7e440555df45d93a8d5520362870c8590c522656fe388867a67ab1ea0003566b651b7df1e5b41afd2c2fb2a8b8b60b73268a0eeed128d8cfda10a66111f5acda3f658262a40326da712b49b12483c92f05672bb484813474bb41d138efab8491c0a95cef372d7f3a21d69303787ccda217aeb5f367d279931283777cf233b09e1a4e8810a073089097fe2951513bd285c23194e949709a438c614e4b00459b746558be3e3560d1434e2ec2da516109113ea2bd8b048dde3d0817b791f4f8dd6d621c6bdbfa2cabde46e7cbcf0e18e57d57ac3f69f18ae5fe7bbc8ed04ad85ddafd29c14b5891462e4c0a810b48fd53ce68ff0e7b5400b3de4e07377c48aa83428ddfb1a11388c93441434bacbdc552fa911b6124bd9e43bd95e700aff4db860b60c457352e314ddb6af8fe87a5b0a24d16338a9de5e28ce1756a3d4197cb2469003bb3e4c2cd94ef3b16c40b38385f3599b15ffdc869733f1b981b247939bc1f13df8743
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24328);
 script_version("1.28");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id(
  "CVE-2006-3877",
  "CVE-2006-5994",
  "CVE-2006-6456",
  "CVE-2006-6561",
  "CVE-2007-0208",
  "CVE-2007-0209",
  "CVE-2007-0515",
  "CVE-2007-0671"
 );
 script_bugtraq_id(20325, 21451, 21518, 21589, 22225, 22383, 22477, 22482);
 script_xref(name:"MSFT", value:"MS07-014");
 script_xref(name:"MSFT", value:"MS07-015");
 script_xref(name:"MSKB", value:"929434");
 script_xref(name:"MSKB", value:"932554");

 script_name(english:"MS07-014 / MS07-015: Vulnerabilities in Microsoft Word and Office Could Allow Remote Code Execution (929434 / 932554) (Mac OS X)");
 script_summary(english:"Checks version of Word 2004");

 script_set_attribute(
  attribute:"synopsis",
  value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a version of Microsoft Office that is
affected by various flaws that may allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Word or another
Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-014");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-015");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0671");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2023 Tenable Network Security, Inc.");
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

uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  off2004 = GetCarbonVersionCmd(file:"Microsoft Word", path:"/Applications/Microsoft Office 2004");
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   ssh_close_connection();
  }
  else
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", off2004));


 if ( buf =~ "^11\." )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
          # < 11.3.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 3  || ( int(vers[1]) == 3 && int(vers[2]) < 4 ) ) ) security_hole(0);
	}
}
