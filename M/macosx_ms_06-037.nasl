#TRUSTED a38953800d3cb0e72c80833f0450a3d6d659139b66686ec4f55bb41386f8d43040d4ade99c1d74ff6fba12d50268794447b092a4b710cd51aa38f4aa722cd8adcbf6b904e98d84e297434398a1d6eaed28737b702c12701b64272c6f3d4b9d3539b3508dce3f749049e31ce08d21acbbb1c16ce3d281305688be12168214208dee890256c9560594fb3741c65a178dfbeae608fde2d2bf2163c85f13297192eb2189b06f6ec77ea5bd26833c21e720d26b010f711f378484b58fe6c01795c08d5abcc062eae14cd1ac5f3c63c850c7bdbc50a985c77b0757b93a139f389b3acc1fb9e30bd6ce01c5308d42684733a1ef8633d97c1eca91305245f7b5499c4f184f3c05c36d44ea89ebc8be4df4d0da236a2bbdfb7cf121d3a9ad97e6131a9e5d623b8447d7c04fa4bc234125319b2ad44cc37af199a2906529beeecce8f857b0324ee7a7e5b5065b718c48296bb503000bd1fbdf86b529a5a5a6e902e7416d22bd130dd3a584dd4b8489ea6fc33970a0c0fbde7bd6668cd2fbbd50017cd610cda3dce4a561fec71ad8f11a766a73269622e89ae6745e1522540f1ffb06db8910958b7e77581c8f8d6a08dd9a056c7ce0e568b9f929558989a3cbfcafcb4ae50ca7f18b83b265b5a24a4b2b6f0d048b25876ca713477d39cbb13f0f0c04180fe0257022af3ebcf282a78412fcca14c4f6d9cb247b468f71a115d9fae7fee259ae
#TRUST-RSA-SHA256 35aac45db0cdd0b0e0f84a6b7c8067be775a400971def3faec31a582ae70f5612f6112f7a1652c9caa10c4369ec570f0cc9d78bf9a49fb97ebfad4869cabdc0dde79e60851a1c28ce4f181405bde32ec17b528c6eb14bdadaec76479264e00acdccc297ba632d6bf81d03d0bddcdd423d3191a1bb33a710c42353569091fa4f5878f71949ab38e427cead30e76355fc9fbf350df02faf1c0b22eddd795bd0b5db3dccfc72a1b4cb25f552016e159ab4d45705badaffa069eb6dc7cedef7985717e076c3ddb38410e4e9777f8c6231aa9c926ebd1ead2ca3e797ff70628f76d2dd990f2eda136e3e69075a12fa9b45d68cdde5f318f4b6d53f95a9fc150af2d499d1916ceaf8376b57f350ef8e7c20b1b1ec5ce7efcf6b06cf359235badba4d83081853ced2ad6264277772468aabdb0a1e3dcde5c7e60d48b1d8939c3ed79432eb4d5bb3e2ad72cd600e6454d9d2c8dcc536eca56205d09db9def1354dadbdf29c8d541d6712a2d3b7645e5f8a36c5e90a27e9ff4507d84a7f560202caaa1188d4bd070f1bb557070bf9841a87fa4b648dba1fbc0ec2d03b3a7c96b5252be50793b2fb88a33b264dcc3f6b3242f3c662797b91788131802de76ebb8cab6ada00bc895e3450ccbaf11439fa33a2105778f9b3e7d5d162a1f2d81d34976df5422ed15ce9d6b7e73a55ebcea9fd4e74428e5cbdff9de525847cf2366373da736a3b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22025);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id(
  "CVE-2006-1301",
  "CVE-2006-1302",
  "CVE-2006-1304",
  "CVE-2006-1306",
  "CVE-2006-1308",
  "CVE-2006-1309",
  "CVE-2006-2388",
  "CVE-2006-3059",
  "CVE-2006-1316",
  "CVE-2006-1318",
  "CVE-2006-1540",
  "CVE-2006-2389"
 );
 script_bugtraq_id(
  18422,
  18853,
  18885,
  18886,
  18888,
  18889,
  18890,
  18910,
  18911,
  18912,
  18938
 );
 script_xref(name:"MSFT", value:"MS06-037");
 script_xref(name:"MSFT", value:"MS06-038");
 script_xref(name:"MSKB", value:"917284");
 script_xref(name:"MSKB", value:"917285");

 script_name(english:"MS06-037 / MS06-038: Vulnerabilities in Microsoft Excel and Office Could Allow Remote Code Execution (917284 / 917285) (Mac OS X)");
 script_summary(english:"Check for Excel 2004 and X");

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
the remote computer and have it open it with Microsoft Excel or
another Office application."
 );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-037");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-038");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office for Mac OS X.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3059");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

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
  off2004 = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office 2004");
  offX    = GetCarbonVersionCmd(file:"Microsoft Excel", path:"/Applications/Microsoft Office X");
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
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_warning(0);
	  else
          # < 11.2.5
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 5 ) ) ) security_warning(0);
	}
}
