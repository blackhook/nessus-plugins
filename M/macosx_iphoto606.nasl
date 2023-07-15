#TRUSTED 9b92f4815c8df673a05137ed54728daa68233ef2412f269b28c89b8838f64cb2377550eaaa946564d2eb14810d8d223c01c3db74f938301d89ad93720b658d6b91345eddfcdf2d3c8c3bbcaca16ae79d0952b860bc0f811fa650769a3008a882063e412620b3a3a9e6f8bfec57286e4d3c12ac9fa61b7b87f5d36a93685637ca9da57e4c44e5fe44bcd6fe4fc944d4a708f0198bb3f3cbeec0dd414f0e3496c1e80335f9588c48297b840c92bbf9dc3d3391474a7a63b05a3aecdd2f8f75787670a3fc07d75f4573adda9ff415eb89fd022b7504203fbf0ff8c1912062b2cf1c94ed49c0717b5899379f350301e3dcb2213b9f63331aa30ef555050c1d05b3fef3bf859973576580abf8fbf0db1484f7b2aa7db53e14b97e9bbc523aaf81bf869d6432e5046ed6a29cdc0bd075fd611ef0f5b4b9caa391882d593f9058a078a6389d7888f706955811976fe95fa8f38ec0295ea67e50b6f267e8869616868f34cf5ff79597b50ef93fb84ee63e14216efc9d539d1648a3eb8d92147addba0b11bbd29facb08af140d370a6e59ed045868a5f2fce77cf42aabb95ec12a800a0141d32185e669855c2fdb8c33fb839765565ad8c8526d60be1f401ee46ed83a2c7f5f5c0099e3dd6602d3015cb15947b0f2f8765807ff9fe48544d5d4c895cff19e86dc7e261f7053df44b4aca5e4973ec3d679bd805f55b9c730cba0c62f6d92e
#TRUST-RSA-SHA256 8885815cbdf710b1bf99acd80baed1db3f16b22d6a5b26ced6396ed1a4e0daddc2645a18348247418e18240fd612446570741d2771704e2518b4b05d1b00c5cf6058c68753817ef640558c334134e1c2eb550da4ca2c9c66b01ecf82c5948ea6fcf3e386f23471493e946c580f206e5baadac624de7acedac1bc3726f9e3a439338843e944d29e81c3d89cb0022e4722bfce29d67830e761793fb71f3c55f0f5d082cd79e60f5ef63272e180790598c108e8eeb564b69a4d682e4f1e2f9880b1c4a906e337a59497af89e12375294a3bc27549cff2d28dd3e1c2a83ffa5bf465a68463a172c4fa6e9b25450aa743475721ce8771a17022770393adf59af990d143494866c8c0a66ce1e47ed24195abdb59d0c3a3e73bcaf3b30cd29b394bdb76c692e2a6e11f9cbfae08552e4707e4853d42d756971da4ac60b24d2b92e14b2b525e5853e1e3fb197c2fdbafbf87018b4e745d0b9c1a14c5a245983484b776562912bb8c4f6d722372c9a2eed7ae8ecb0bdfd8c4052937a23aa9f90fbf47badb0a3e61ee547c00941a0a52fe70ec3151e1d550b9a73e6c9d7c2dfec77d3f99b3107d75f7feeca65eadee562ac4e5a48f3c06b893513a336f26f4dd04bd98f0b7af7c5214342f02c655a5b4eb46896956d512aae224afc54821bdc8ffc88076ae57cdcd2d60d22734386ca194319e37b89e78332c4b2f335191683dc3d99a167b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24812);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2007-0051");
 script_bugtraq_id(21871);

 script_name(english:"iPhoto < 6.0.6");
 script_summary(english:"Check for iPhoto 6.0.6");

 script_set_attribute(attribute:"synopsis", value:
"The remote system is missing a security update");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of iPhoto 6 that is older than
version 6.0.6.  As such, it contains a security vulnerability that may
allow an attacker to execute arbitrary code on this host. 

To exploit this flaw, an attacker would need to lure a user on the
remote host into subscribing to a malicious photocast album");
 script_set_attribute(attribute:"solution", value:
"http://docs.info.apple.com/article.html?artnum=305215");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305215");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0051");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:iphoto");
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

cmd = GetBundleVersionCmd(file:"iPhoto.app", path:"/Applications");
uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  if ( islocalhost() )
   buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
   ret = ssh_open_connection();
   if ( ! ret ) exit(0);
   buf = ssh_cmd(cmd:cmd);
   ssh_close_connection();
  }

 if (buf !~ "^[0-9]") exit(1, "Failed to get version - '"+buf+"'.");
 if ( buf )
 {
  vers = split(buf, sep:'.', keep:FALSE);
  if ( int(vers[0]) == 6 && int(vers[1]) == 0 && int(vers[2]) < 6  ) security_warning(0);
 }
}
