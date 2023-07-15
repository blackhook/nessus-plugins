#TRUSTED 110be0ac9bbde9429bd7b46e369c5b4e0188f13dc244b3b0ff431285543de981485fd2ddfe76f003b823a2a1655a4170c585ce9a8b5e4887cae5c2ca26ef70a2d23cf629012e8b03f80331296d218e1b47b2293765043fe053ccf3a1e6a60a14304597f1dc1f1a5c4ea8fb9a7d8953a6057deff43ad9b4e5904be268cd67e1eb8cfa7ba0f3b2d9dec7cd22c97dd218a43ae401a997225f013d84df98220208c08f77ba14775973a840feb924402e46df5a36e6a8d545096342203cbc1e93f59bd516ef826af7c9ec0aa42103de45d680549fb374336e0f2ccb8fefaf8f377170b89d4884155f81db296e06dcd65156817a85f35e24779de65ae5858351b05755ac828c74f920a22e49e6d63d53d575566eeb2b15b9416b42bb7fb3661c6ea4bd8a0835cc4585510421bd8f41043a48a936e0055ceb6f079a0109b768b3673883bee89073d47932b8fa677e712a77a735116b277afb4492156b8bd88e02e7a703ccb9bb8221ab41a0f6f73377d096afa7277c2b9c0c85bae1cebf47f6e66bbe77cf30db2246b79fb30dd9212f9984e3f9fac429a9016c2b595c37fd079adf9ff7936ddc13420cd2e78698c6fea7221b2ee7641df69ca9fe431c299de4ba1fc611e752fada48fb661843321efb4dd306321f1350edaab22cfd771930eb266273c64ce7c82c1d51d59579938fd2ef70b1753853f85e34f71dab46c82a92d6aef7a9
#TRUST-RSA-SHA256 a8ed36398540db3989bf8b80b0dc07fe5399959f9572fd13d8300d9c1e52110d97442bfa6d9a4a23edebeea52eff9de2800ada4fa8ba75dae3d4bd294326f161933532a3d4ade7b713fc72c687dd116ed143489df07ad86e906a51ed49c21b70338a9b07fb06de28308d19e97425db56ca735d6ae074accc95a803dfba5574f2522c3bbdb058764aa4861de98f9ec2001441ed365acbce52bb85758de2f314782fc540b99933428d2507e4ebcd9a311a64ff97bed85bc7258ed9905cf065c6530f1aaf57fbad27b1d1d77617dedcb31676d2959794ee952c0810ae5ad19930e27ba03e4279924cde3979079ab251eb2fd64f8511101129f0c30b7e17a358f0cc33aa4ef0f0f6f9bff5e10e393fb3ef7c9c1dd2425e3f104357a5e0cffc83125ae77d1fbdd406587c22cd7baa6a8cc82c090ab5fd538a1d8985c57edfddc278377ac1f2aa0954437b0523df6e7fc73239783f0b1315a0abe415029c0c7d60a236bbb2fb460e848d201743e3323e05f278e1b90e6762a62844ea048d36b64c7677cc31e4b5b42c382a706cba6b6d8af36f0db4c76bfd4bcd10137239f353987c69898765a65a086999df41438e12fc7b658f2c0f3da9c5431955b101c25ba2b0a499fdea7916439e78fe1b5b505005facadac44d9acd180272bb10f30a714af11c4d852fe8ce57b4b4b46e9a633f5097aeb1459dd5b7361c2dd1d65eab6d4eba8f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40563);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2009-1133", "CVE-2009-1929");
 script_bugtraq_id(35971, 35973);
 script_xref(name:"IAVA", value:"2009-A-0071-S");
 script_xref(name:"MSFT", value:"MS09-044");
 script_xref(name:"MSKB", value:"974283");

 script_name(english:"MS09-044: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (Mac OS X)");
 script_summary(english:"Check for Remote Desktop Connection for Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Remote Desktop Connection.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop client that
contains several vulnerabilities that may allow an attacker to execute
arbitrary code on the remote host.

To exploit these vulnerabilities, an attacker would need to trick a
user of the remote host into connecting to a rogue RDP server.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-044");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Remote Desktop Client for Mac OS X.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1929");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_client");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  file    = GetBundleVersionCmd(file:"Remote Desktop Connection.app", path:"/Applications");
  file    = ereg_replace(pattern:"version\.plist", replace:"Info.plist", string:file);
  if ( ! islocalhost() )
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:file);
   ssh_close_connection();
  }
  else
  {
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", file));
  }

 if ( buf =~ "^2" )
 {
  v = split(buf, sep:'.', keep:FALSE);
  if ( int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) == 0 )
	security_hole(port:0);
 }
}
