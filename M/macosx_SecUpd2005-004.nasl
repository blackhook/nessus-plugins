#TRUSTED 852e19bcae2109eac7c1813b30eb8e7fc504b542c9b0cc80b9f093c4c0c274645f7aa665a7cd03d6fb91ee06d996011badf5989027fe95f40fc37403e02d9223e4ad8d7a8d03a69a5dda4f90bad4a2a252fff6fef6837dec7d2dd25600a2b3595370345289fda92848b5afa93eda28eb2f004a7fa0e6c2501e6d5492ff4227288b36e2eb1b57820917a48380a770f8e43cdaf3e049c4e625b1f0cc2cdf5bec32f8d7a406999dcf6aa4b68394e2a6c50895b8ac51f4bbad44a271737367efe27cedca9338a53dc0aec8acba2b2629ebcaaed5dc43c2896842930de71f415df55354af7f81d164f0d6233e6f86f97312e8a6f6b841d4f50184274162bbc5950e1af7845c7c56750828c00881e10c132df020beb2003602c7243fd1680848a8ad11b2e6867676a91ba553029336f1040f2538cabe901ae680f7951aaa706c6e6fb14d4aa5bb391d974857a9862d5ef2925844831a3882e6ece16c3dfcbadca019a27fa069805034202ae85240659b3d4cd260a1333593ffeab64780158a888a229a57c688a977d4bbbaf7aa605f8421858565d4c4217e54a02a82a0b012a93972ca2fbcaa85c31c2104275db62f5613198700eecccddff46e51760c599f7dd11a952bfefb45a710926c438d6829a591c679544f8976e889568d63097031a6785ded783bb87100f1b2e6c0b215bbd8581d730aa2db27c6b815441721d48b8b1e6cf1
#TRUST-RSA-SHA256 462ea909dd4eb90ff9cc6b15f5a99d7a6a3ffe4d7e1849302557f19a247171155cc9b68dbfc2f3d117bfb38d0960c397838facde9eeeb56e050bc0c26ed227bc6e0346af904cb99d742f4dbdc1bc19c4bf6aec8b2720671c971fe45ac9f3f1ac28678908c2d0698a9d638bd05a67188fe0ee8ce0b2be3ba62ca8ce9791c06e8206054760d0e32ebbd250da0192b5693648d3c6324b6a46dbfede2d83433b2cd3b9147c43cc2e156851ef24478e770ddd7e393edf804fc4718eef1a489420c57f8f1a19dd4972ff5a4d4ef204307fd29a4f10daac79900d91a8bd1a117c91be8632aba59c37d7ae91ae7a280b21d182ba007dead66f86c1d9c556ff55a63e05abffa0014bd59e9289b71df65affc710a188e34a4ad0158a43687fa29445e41215d1080f8805ef0d372a8fb1118202dddbc82cf8e739766ca7d6a6cf15b9a68bc091b55026ea0c755f54f5257365dd2c0a3b52f53941c514df9a5f6250bf8606668ef594771e2ae4070661e24891a00ac8230b0989845e5c20e2d689e3ecbe1bf6c8109444307f7ae029b0d0e3d4fd280dddaab7e19055449da448aa8baabd9d47ed4750e8e23a1874c938dcbb272bddb9fca763b4cd0a81f4657b09db9538b9a88fe7fc2bfbe5146cc9e640bdeb786a20656818f00f320f198e44ba2926e5f7490135a0a0d12ce232c54dcf74a6f805e378c8d71c27b03d210551a2ee3077e0b7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18099);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2005-0193");
 script_bugtraq_id(12334);

 script_name(english:"Mac OS X Security Update 2005-004");
 script_summary(english:"Check for Security Update 2005-004");

 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is missing a security update.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 2005-004.  This security
update contains security fixes for the following application :

- iSync (local privilege escalation)");
 script_set_attribute(attribute:"solution", value:"http://docs.info.apple.com/article.html?artnum=301326");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0193");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");
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
 local_var buf, ret, soc;

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
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
 cmd = _GetBundleVersionCmd(file:"SymbianConduit.bundle", path:"/System/Library/SyncServices", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) > 0 && int(buf) < 840200 ) security_hole(0);
}

