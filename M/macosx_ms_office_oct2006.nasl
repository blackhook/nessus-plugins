#TRUSTED 63beb11ec4d6376385940ca8d9d905b734c2c138c778e6dd2a8a4030b6edf21b4e8ba9eb3871667e2cdcd32f6cc13bddc30bbdf22359c6d626281bb7e1a987b658ecdd119597d6a1f92b656278c97d323ca354a7d8d7357e12de1d62abb0e5a83b51891420e108aa7c1eb53a7587c07f47c8a13a3239b1a2128786c466d5ce1122617425ee55de99ee4da46caae6a47f27acbdc0116159ef30691d4384d187ec7b9c00b80bab9e48a44ac21a95bb6b3e836817d28a8d9cc684ebef3364a6b46e5d54d2f56117ea04bf1f96667fbf5398b614d6879d4cced444fcc6547bca1f51845e95b678fc249e6715d30071665a47dbc40f17a698f46229ca54199d01f5dd6e504b39c43fffe8dab539f0dc61235b6880fdae2933903dc6fb93739957b3d892092b83773a2d2c88cbfc8eb37088e055322808187d9989b0496e91a5e588538d63402ad86624d2b6edbeef1f8a17148f8f5f397d76ca58dcc506a826f1297d9fb87769b6e3385ae354e97e9135f9689e72da943d6f524955887977de9dd6a5143625fb70130ef74ecd643a69fd70d4cd85104d9ec79ab7162cf2e8ffd0aa770419c4e6e78ebb5b692f1bba53d7b73e4e685ce6d4de04b08aeb2a2d9024cfc6c62c90c1a68b4f441b374762c2f2539d3310029002aeffe333a5d9d92b44f8efac260244bb624d025d29376668fd3f8933a32bd40352d740cd16b8ee535a2915
#TRUST-RSA-SHA256 5c9c3f6dfc7f448b8034cfa877013de3432b2d7d8ce031d4eca5eeb035bc89f78fc735c0c73a77b10dc48ec0d4bc06e0bdccf143d406f8a0656c087d0ae4d049be738092f0383f7db5605f01a07d822e252748e24ce206585900f0b7055c6ffcd700eae9dcfc94a4b283939b1f00b9e393982ea5c9106a10579d0712750cb0cd8b3bd6144843f3aab81684af7e16a6da667e73f0ce9873d802dba46a158b3b7d6ccadd29ff7f9329db6c4662c712d3b846295e500b23a012608352284d64d82c9051056665e5297b2d2ee02077999b9bd85c94116a9599f998914a98e8e3de3bb116d665227df58e0f8670ccc947d715012a7379cb8ffcedd2872ffe5ab701b31342c5c02a26b09579240531e5a2467cd3f318ccf344b1dbf17864b9fe5aa7100cfca58d358290c0ee6c79165192ffd3fd1d55babcd359845d403274bcf8b0bc6987fcd045f98d08ce0a4100e18324fc42bda89f2adbe11b415f1723a5877f707091334b3ea05bfedabed6ba7812e747126fa935e7f68d0f9fcc10edbd867b12a1fcc8d490e25331dfc7cdddc0912e6166fc38b85c5e9f43d0502139d01208e12a92f4a512b5faa3c0681058a807c5ef2a74c2acda1049559c06f6ce89b580a26da3ff868aec5fe5e94c57ad1bdb600415ff55b542e86bda9c88574996d0ccf237a8c33c18db46059579b3d6d54aae0979f8aaa4f6f2684a7201acf99294613f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22539);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id(
  # "CVE-2006-3435",
  "CVE-2006-3876",
  "CVE-2006-3877",
  "CVE-2006-4694",
  "CVE-2006-2387",
  "CVE-2006-3431",
  "CVE-2006-3867",
  "CVE-2006-3875",
  "CVE-2006-3647",
  # "CVE-2006-3651",
  # "CVE-2006-4534",
  "CVE-2006-4693",
  "CVE-2006-3434",
  "CVE-2006-3650",
  "CVE-2006-3864"
  # "CVE-2006-3868"
 );
 script_bugtraq_id(
  18872,
  20226,
  20322,
  20325,
  20341,
  20344,
  20345,
  20382,
  20383,
  20384,
  20391
 );
 script_xref(name:"MSFT", value:"MS06-058");
 script_xref(name:"MSFT", value:"MS06-059");
 script_xref(name:"MSFT", value:"MS06-060");
 script_xref(name:"MSFT", value:"MS06-062");
 script_xref(name:"MSKB", value:"924163");
 script_xref(name:"MSKB", value:"924164");
 script_xref(name:"MSKB", value:"924554");
 script_xref(name:"MSKB", value:"922581");

 script_name(english:"MS06-058 / MS06-059 / MS06-0060 / MS06-062: Vulnerabilities in Microsoft Office Allow Remote Code Execution (924163 / 924164 / 924554 / 922581) (Mac OS X)");
 script_summary(english:"Check for Office 2004 and X");

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
the remote computer and have it open it with Microsoft Word, Excel,
PowerPoint or another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-058");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-059");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-060");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-062");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-4694");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2001:sr1:mac_os");
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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
  offX    = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office X/Office");

  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:off2004);
   if ( buf !~ "^11" ) buf = ssh_cmd(cmd:offX);
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
	  # < 10.1.8
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 8 ) ) )  security_hole(0);
	  else
          # < 11.3.0
	  if ( int(vers[0]) == 11 && int(vers[1]) < 3  ) security_hole(0);
	}
}
