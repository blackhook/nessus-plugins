#TRUSTED 2018af5d8eb83d55feaf3e23594a49a85503e9c6dcae62db543e40be01702214189eb4f4dd9267ee47eeace2a8b00c98b039e48b1226594f70ce500aa659d225ad24710773beebff7212a171ae749af15f5a529b1e755d2ff7c141eb9dbe703d1a51e07e0dda631a21892e20cc8074162caa177a3ed7ad07960a2edfbf73d5f1934d5920952820d22a95e206eab058f5ef09bead3c9623da2803a8b02800b9d5894dff865cef2d9a731f1c64fa85793ebb50872fb3eb0077a6ce45a409383df30e4d966bfdd85011543e22d40d6f0e2fc6caeefbeaa403ebc4e1af4d7f625d26dff815579aeef88a101688a7c7fd11f832206cb7a6b2c3a466acbe943ab499dafd10cc9e458f6ed091584ffb2eb62f778794f19cb15b6fccdf35899a632a61b444eaf132d550878b497ba283f833c24383391f6c604faec63436063c5c60cdc111bc83d3771dfe8a427c37f685eb49113178f85789e74156cbf5032a8dd1fd8ebc0c3a3e70bbc7b4611abf6dd1e592bd2893da622b7d26481b48fc15d0ff4b32d012f2c2108e810c5d0db128b94b46367b2b8265a458b90b7fa5f2830afc4770a6df32910d01bd691ca02137b96447c368bb6537801e512733d5691031e3ba0c7c6bee709a3c4bc837705bb327c74a9be9bed4281dbb681ede41405be9909e19aaa29fed241eff1fd9f3b0a7b83ea28a3f0edb124efb16f450c7083ec49745ee
#TRUST-RSA-SHA256 a3b97bc51bf8a0f41e954fb5f75e02f3ec78be2608baec6322bd7b605238d2eea02a9730ef120b5327b24023b19eacda7979cd26b764f281f201ab7ad7a4472b81de9422125109dfeacc3f2fc392e784faf3419230432195acfbba86207fdb92009e4ec8a7e849aa98cc3a4e80eed3ba4319b5f3f8a10ce6ed62b4988de504d13f5fcd78bc2dd5a124d13ec6041b7500a3ba8c1dbf8ece9f31a49976944e66c0f8ef73302fbdabc85a82ea09a43cc9124806de2f802327690ac108d7465434cea4a8a299d40f331a65707bf4d42264d548cba1b03efb13b52458cff91f780a1f0e1ff8175de2f9a5fc676093b797e3270e5a75130e2d655a3ffe77326d8719c474e5b620221b4f28fe1903b84619faf18bc24ecdbe84952a44645029f43f0e76c37e3af2d5fae39b4b40ab22e793048631bbcea76d8a088a1d9f00a38a5e0a00fc8e22bc8b87175ea401ec589d13ea5a48e88ce548779a6e5be9989db81e70b7dce684668a9a3991c2e5c8221b6f33bf5e05f7cb9cff8677aa4f19efbb21247a9902b13a6be6e6aa7755f35a3660fb53c1af0ea8e9d116d7013acb4df8d2f8248bb1986f9383be423e796312ad58778a4804c2c9d35550dc1891ea7986996616cf2f1f609099c1c85c2d29fa5975979b11a39a68d43a86133ffeb726a488f800a97de55db231b2a2f9143b15856c30324e1e1ab839990ad0fa244a7c563777f3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25173);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id(
  "CVE-2007-0035",
  "CVE-2007-0215",
  # "CVE-2007-0870",    Microsoft Office 2004 for Mac not impacted
  "CVE-2007-1202",
  "CVE-2007-1203",
  "CVE-2007-1214",
  "CVE-2007-1747"
 );
 script_bugtraq_id(23760, 23779, 23780, 23804, 23826, 23836);
 script_xref(name:"MSFT", value:"MS07-023");
 script_xref(name:"MSFT", value:"MS07-024");
 script_xref(name:"MSFT", value:"MS07-025");
 script_xref(name:"MSKB", value:"934232");
 script_xref(name:"MSKB", value:"934233");
 script_xref(name:"MSKB", value:"934873");

 script_name(english:"MS07-023 / MS07-024 / MS07-025: Vulnerabilities in Microsoft Office Allow Remote Code Execution (934233 / 934232 / 934873) (Mac OS X)");
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
the remote computer and have him open it with Microsoft Word, Excel or
another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-023");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-024");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-025");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1747");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/09");

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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");

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
	  if ( (int(vers[0]) == 11 && int(vers[1]) < 3)  ||
               (int(vers[0]) == 11 && int(vers[1]) == 3 && int(vers[2]) < 5 ) ) security_hole(0);
	}
}
