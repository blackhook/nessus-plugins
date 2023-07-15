#TRUSTED 2db9047cc90e8c2223abca4eff9db1289b82d98e592e8f90b1109afb1ba1b952084db20eff2c6ae932a55d92ed4a2e6ff407f70e8acce12e1508685a7cf54b67e7299febcb5d55946b08372fc5c8639d64c5e6afbde459907e1c3b95bc543dbdc957dda440ee9bbd5a397dfb696266f070cd89af0beeb797ead340d5849a2cef7aaa1edf00f6a8367a677086f6db9479e6ea90569c64dd4b61801624c27390b7e1c91184b9e999db27824208e1e4b02ce400f544a998b85070404cf0b72c08ff0a2196f589dc8272c09f087bdb6007b41a5b3ead5072e2b25b5922ad85fb13f65da8cbe201ccd2b40d762f498bcb6063d5efc03c4d6fb61910e344bb5c7daabe46f4cc46004726eb951ff247f70253973484bf2c032d37008c3d2adc5521c9be7c225e219760e57ec97e867d68ac935e5dd238cc3014fc812448d6af3d72c385a0d180e453c65d51cc019d06dce51fafacfac903794b0b1a1944b8f57f2c1b5b8cc8e63cedd5ca5dc9301a7e68877817c4874e0ab170e0ae41d7d74ecb412b2c963551ad7c28625a1117ba5ab4e9be20b85db4bb488e86967bc6aded5560dd2d811eae144f265eb28f72320715c258513cdf2bb39621fc408f1367289065c7aab8af9c64d22824413eb4f0d2aee99064eac55c477c3207c1e5405be6e6dc294b2ca4a41714f8ca43072c7a68f735f552ec66db93bf21d46ed4159fcf2e7f13e8
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include('compat.inc');

if(description)
{
 script_id(34030);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

 script_cve_id("CVE-2008-3844");
 script_bugtraq_id(30794);
 script_xref(name:"IAVT", value:"2008-T-0046-S");

 name["english"] = "Remote host has a compromised Red Hat OpenSSH package installed";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a compromised version of an OpenSSH-related
package installed." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a compromised version of an OpenSSH-related
package installed. 

Even though this package has been signed with the Red Hat public key,
this package is considered malicious, and the remote host should be
reinstalled." );
 script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/data/openssh-blacklist.html" );
 script_set_attribute(attribute:"solution", value:
"Reinstall the remote host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3844");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/22");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();
  
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Red Hat Local Security Checks");

 script_dependencies("ssh_detect.nasl", "ssh_get_info.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include('misc_func.inc');
include('ssh_func.inc');
include('telnet_func.inc');
include('hostlevel_funcs.inc');

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

list = make_list(
"Host/VMware/rpm-list",
"Host/RedHat/rpm-list",
"Host/CentOS/rpm-list",
"Host/Mandrake/rpm-list",
"Host/SuSE/rpm-list");

flag = 0;

foreach item ( list ) 
{
 if ( get_kb_item(item) ) flag ++;
} 

if ( ! flag ) exit(0);



if ( islocalhost() )
{
 info_t = INFO_LOCAL;
}
else
{
 sock_g = ssh_open_connection();
 if ( !sock_g ) exit(0);
 info_t = INFO_SSH;
}

md5 = make_list(
"00b6c24146eb6222ec58342841ee31b1",
"021d1401b2882d864037da406e7b3bd1",
"035253874639a1ebf3291189f027a561",
"08daefebf2a511852c88ed788717a148",
"177b1013dc0692c16e69c5c779b74fcf",
"24c67508c480e25b2d8b02c75818efad",
"27ed27c7eac779f43e7d69378a20034f",
"2a2f907c8d6961cc8bfbc146970c37e2",
"2b0a85e1211ba739904654a7c64a4c90",
"2df270976cbbbbb05dbdf95473914241",
"2ff426e48190519b1710ed23a379bbee",
"322cddd04ee5b7b8833615d3fbbcf553",
"35b050b131dab0853f11111b5afca8b3",
"38f67a6ce63853ad337614dbd760b0db",
"3b9e24c54dddfd1f54e33c6cdc90f45c",
"3fa1a1b446feb337fd7f4a7938a6385f",
"41741fe3c73d919c3758bf78efc437c9",
"432b94026da05d6b11604a00856a17b2",
"54bd06ebf5125debe0932b2f1f5f1c39",
"57f7e73ee28ba0cbbaad1a0a63388e4c",
"59ad9703362991d8eff9d138351b37ac",
"71ef43e0d9bfdfada39b4cb778b69959",
"760040ec4db1d16e878016489703ec6d",
"89892d38e3ccf667e7de545ea04fa05b",
"8a65c4e7b8cd7e11b9f05264ed4c377b",
"8bf3baa4ffec125206c3ff308027a0c4",
"982cd133ba95f2db580c67b3ff27cfde",
"990d27b6140d960ad1efd1edd5ec6898",
"9bef2d9c4c581996129bd9d4b82faafa",
"9c90432084937eac6da3d5266d284207",
"a1dea643f8b0bda52e3b6cad3f7c5eb6",
"b54197ff333a2c21d0ca3a5713300071",
"b92ccd4cbd68b3d3cefccee3ed9b612c",
"bb1905f7994937825cb9693ec175d4d5",
"bc6b8b246be3f3f0a25dd8333ad3456b",
"c0aff0b45ee7103de53348fcbedaf72e",
"c7d520faab2673b66a13e58e0346021d",
"ce97e8c02c146c8b1075aad1550b1554",
"d19ae2199662e90ec897c8f753816ee0",
"de61e6e1afd2ca32679ff78a2c3a0767",
"dfbc24a871599af214cd7ef72e3ef867",
"f68d010c6e54f3f8a973583339588262",
"fc814c0e28b674da8afcfbdeecd1e18e"
);

res = info_send_cmd(cmd:'rpm -q --qf "%{NAME}/%{SIGMD5}\\n" openssh openssh-askpass openssh-askpass-gnome openssh-clients openssh-debuginfo openssh-server');
if (info_t == INFO_SSH) ssh_close_connection();

if ( ! res ) exit(0);
report = NULL;
foreach md (md5) 
{
 if ( md >< res )
 {
   line = chomp(egrep(pattern:md, string:res));
   split = split(line, sep:'/',keep:0);
   report += 'Package name : ' + split[0]  + '\nPackage MD5 : ' + split[1] + '\n\n';
 }
}

if ( report )
{
 security_hole(port:0, extra:'\nThe following packages are vulnerables :\n' + report);
}
