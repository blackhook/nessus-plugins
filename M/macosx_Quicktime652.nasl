#TRUSTED a65156b9e1d6dc233d86447e1f93ac80bfbbabd7a31ef55921d92bfcb735f98a32bc2ea976d66b6457f1bc29fe4088f8b4f990f8b4ee4ed59351715cc5c0af209ec66487d3f3967aa80d3d00a816c70b0daa68a739fc7235d4361a5fa1aab3c24e414a8949edb64b4fb99aa71c535cbc7593b3d1ec624685fac0b4c146389f961c76b35a2895efb9577ba85c9c32654ee3f746e1c9016ae8279d3482a7b7ed8b37c6883cf4a53c3c909a1287a0a1c32696b0d855fb9a7f84a2419cc9c444ee36fd989b3ee330ca3f264d7559d54a24bce3eed1905bfcd818baae68f9a4ac83a0a1e4ae5bea4b3a6146eeab53c2275881662459d19d985433f2042a4466389f042420e7f342323230cb6b662a87317ae29b70b2f276854e24add63747d6150a33c16621c8d9be8f714324ea7cc3efb7ae116edcc0202bde6d754c81db0f6dc8d9f72c03888e9dcc08e32c90d201967ac165348ebeea88a7b671ea62031831e8dc9f431f1c7cdb5e6f7f379f09e540b704dc2f2269b19ad251e273126d0fb81cced375b0fdb697d82b0832617bb1fc079686a0877f95421f4a1c5c55470668763bb036fd7e1ace30fc1f189316c7fc86276a752671e112aac4d1e03ef3417c338304ed690e4a4e769ded50ad38051717489ee77d6961a70e91f2170d69f6c9a831c862d3be33ee402cb05605cdc64c90fafd1fb82ee94554be64016cc9f6b3ec92
#TRUST-RSA-SHA256 41b8deb55595f58ad3027ce35b1aa9fb3bfadb7c4943172c9e871cf612b0768b3d7e4e5aeb5247b0859012e7fe0adf68f5ad1a5d94685f677d56bab0347e18e21b34bb4d50beb9b866300aaed06e886abb85aa22659c3a79fcb315d725386d1aaf6e54e451329367d818762e8f8d32e1d6991489ef85439ce3a0c8c066114b2f11ef202e4773c8a79e0e0e9d8babacf480fc68d3292724ca9374aa8d9a2c846591181cb583dd5d08cceca486d37514803fd491377cf30be6f404cb2a521bef984e6c0a8d6096d52be83ce95b2040df5783ffbc56817fa53931f3532e3f5ca0f92d1fdaff14e3cdc9cc61fa0d4e740c35398da4cb7dc68f26689d5feb672f88b5199afd4aa709a839f972047302ec88d5770290ae914167dee099f379f99763e6a8562088103ed45231f48f38c1888dd417a4628222cf2b14aacfc2b191ea88c98135dfe62e929eddd43cca86bd3bd5b47fe2193fc26f9114bce9df0d02343cdba331cc1f2aadc6fee8cc77962a6c240d4baabc85165878d769dc721553313b7cc3653dfde69b04440a40eefbe156319f30f2f5b5726d0c72508f6dcda7260fd04966de0b28ebc5ff27db83dfaeb59ba1e7e0efff352c31dd0061b967e2949556036670ce2fe49a0923e3bd8220479160059d39f1486c2b3fa3d8e8edb84228f5340c4d92246894503174bfa4db67a71cdbc26e7c5fb36aa0de4021b0930e174d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15573);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2004-0926");
 script_bugtraq_id(11322);
 script_xref(name:"Secunia", value:"13005");

 script_name(english:"Quicktime < 6.5.2");
 script_summary(english:"Check for Quicktime 6.5.2");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Quicktime that is
older than Quicktime 6.5.2.

The remote version of this software reportedly fails to check bounds
properly when decoding BMP images, leading to a heap overflow.

If a remote attacker can trick a user into opening a maliciously
crafted BMP file using the affected application, this issue could be
leveraged to execute arbitrary code on the affected host.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1646");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2004/Oct/msg00001.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Quicktime 6.5.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-0926");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/10/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/27");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");

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

cmd = GetBundleVersionCmd(file:"QuickTimeMPEG.component", path:"/System/Library/Quicktime");

if ( islocalhost() )
 buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = ssh_open_connection();
 if ( !ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}

if ( buf !~ "^[0-9]" ) exit(0);

buf = chomp(buf);

set_kb_item(name:"MacOSX/QuickTime/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if ( int(version[0]) < 6 ||
    ( int(version[0]) == 6 && int(version[1]) < 5 ) ||
    ( int(version[0]) == 6 && int(version[1]) == 5 && int(version[2]) < 2 ) ) security_warning ( 0 );
