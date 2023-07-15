#TRUSTED 7986f0006366d452a640c4df9c923d584fe0658b045434d0035cf9b4bc573ac69265090ac0652c9b6217c624eabf051cdd520d4edafe7053c7b93e35d811247b8dd022a1220bf7812f7c58cdf8b246552db0a8d9d1aa62f5a289296a550478e7848e7ac5b5e0fe518266c85a6451850c38830571360cb147678f1acaa5b742df1f27b231d789255eaf082f2cf605ac726a5ad5925a80e5eb6c579f0ac463a40a7fb9ec0dee39e134496f08b9511754cb93ebc4730e8c9740b84197fa5b4339b1b9f7df39775f9e789834db926c7c93c4d497d4f83532bab0b34dca76d1a5726f205b1f471bdf41dc3d5eac92ff85fcad8d78409b0212831548fb7b18c883e6dd658f4331be76815593767db27bd5777b4bd60edb20160ff684994485555944d5b792cdb488d3517004d71d327f3ac88d21d680074ed313ec838f2c8489a440d71a9da417118cb2a4c89803eea0b0d3f768b7ff906c5fb84efc5ef99f759cbb203201f7a6e48f757fa0ba287a5b7d0686a504e8abfd7f3d16f6540fa57a8ef1cfe5fbc0bd4215b9fcd4fbb642405593a27f51c3e56ec92f49b31e3feb06477265252294cf7e4689a57c82f55e5cf13bf233339b2a15065ff9c80d0396f722c0b3592e12efc6414ea8cc9ede86104edcfbbf38a1306cad2e50eb90ebc3021d243da7435f554d22bd674433a08bec2e8e534d69075594f55a2e132f6b833194c6c4
#TRUST-RSA-SHA256 09b1c08fb4ec67bcde7d5587a144ccf1865ba2823c19865ee7215fe3eaf253c3de13e3bddafa35b816d60765a44633b42ced31a09b28cfda448ba23c88dd5c6db77c1614b01431b5519f306f53a6eb7e3f96d659a5dad53b80c91ab34a1556ce0a0bad0f2468b1c0bb9e41a4e7d51c30787511d7696d4ad701769eb390835f44aebfa00730e397251164897945f6aed75ec416baf6adac12c25e4bba79a348b3d83633aa547ecd27f2011e64b3cbf70269890f65d45215e1bdb64975e7282edd7e0253561efda9d707fe68bdc14dce9c3ad6a0a442f3ecb44111332d5604d217e19c97c498452c2ed77a4e6b71bcaf49d1acd569b53c8bd700eff1c68bb545f6411d9743434833684cdc886397cf96edb1f60a8416af9e28e7e25392abff2ce2081097fb336183d60eebbc0a59492b744e373644ff759bfeda893e4d43ef9bb98f0cf1f82549eb0731eb9901cc9717c735296c727b6cc16798485306aa92ae9cde01ff7bbbfe44a08533c29fc696429fe76e9eec7da307fa8597d7ce8e5667c7999c995a23f35ee6384492f8eb60b6911e9ad0d375e0b6a5f9502ce4ffa7233916f499a7bf70bbccd0c01376c510c3838627d21e2caacd151553be22e73f812dc7e10335b0ccfcafdbb643872d15b3b9ce2eed00032c75bd23bddb17182d2c253ec4a77cf3a5fa092a7d905ca9c4947b6bb26da9aa2775e23cbc957e41804a15
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21724);
 script_version("1.29");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2006-0022");
 script_bugtraq_id (18382);
 script_xref(name:"MSFT", value:"MS06-028");
 script_xref(name:"MSKB", value:"916768");

 script_name(english:"MS06-028: Vulnerability in Microsoft PowerPoint Could Allow Remote Code Execution (916768) (Mac OS X)");
 script_summary(english:"Check for PowerPoint 2004 and X");

 script_set_attribute(
  attribute:"synopsis",
  value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running a version of Microsoft PowerPoint that may
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with PowerPoint.  A
vulnerability in the font parsing handler would then result in code
execution."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-028");
 script_set_attribute(
  attribute:"solution",
  value:
"Microsoft has released a set of patches for PowerPoint X and 2004 for
Mac OS X."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-0022");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2001:sr1:mac_os");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");

 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft PowerPoint", path:"/Applications/Microsoft Office X");

  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   if ( buf !~ "^11" )
    buf = ssh_cmd(cmd:offX);
   ssh_close_connection();
  }
  else
  {
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", off2004));
  if ( buf !~ "^11" )
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", offX));
  }


 if ( buf =~ "^(10\.|11\.)" )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
	  # < 10.1.7
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_hole(0);
	  else
          # < 11.2.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 4 ) ) ) security_hole(0);
	}
}
