#TRUSTED 8f6abb853f5fa071d6c609b0c310e89d534e2e4056842b59eca657c3dd951eaacc9aacd63210aab81e3ad02b73af504883f5c115423b5cf3827be882d211aa0a33e0bed3fbe44c6d94ddb50332224b0d11f2d465d5bfab2a27c4861571c46971c651f4833cb65b39798183cf5123b4aee94f7aa01b28e617a6dab23794d21f36ac49861baef7109eb61f85dbf9fc1b0f3b1c61c58e7799d733d5079d71eb000b5815a08f5de472ef2da53ad6f4a7fd965b4455a1b5d240835521e6632ac213d9f1508bee4d9b18e56635638385836445fd3607c410278866a6f51da8b46d493c39de02b4b869a9bfaeab6d6e0e41cd769199546afe0a967620d613851275cfebc7c4d1ed709fdfee105745a7bbab52b24c936337039b1bbaf0e74c150f18a31d2596d1690fb21d41cbbfe0021e2e73c67189fbdfbee3b43168135c5fef9822785766e5da38a8a4df6f9c772d8e09a13dbe8a479e9424230a9fe4ea199045e7989e4d77bc793437f435bca5b17de050b00766ab43c0c68d571b59b69b976a8bc49f94626bb2aa0652ea947a1c4c5dda9b4fab9ab3772ccce2caedc92e9a237ee8c2f52538bfe6d50e246ff050ad231db0725de65c24f9dc1d483d15a0be06120623a64a5b449ae883317b76d45769f28d07e17d63ec2f9a8f6efe2991ceb58a129bd0859c0faf8fec7e59818685157794d3b9eb54b121eef21602589ff04f5f7f
#TRUST-RSA-SHA256 7d03a4aa020e80b0e21efd885d3467d56b8ddf718da273753aefce4280c2b359781381096f53a087cd132d00aed67b9d02eb4a8f618b99e94e66be504002ba71d012023d747bff20e24ae066309311eb9dcf629a381b2b6df0748c7a3d3bd558086855c2198f4f4d4450d7024be1fd7829f47bdd044785f7a85fad4a68a50f1c96861f8edaa67855a6b4df6097f8ca2cff1b91b7b4b102a3b66c248864bf9b3eba52603ea1cfaa4f49695c03e2bca94430194a4378b8b1f082788b5138ead78df4556b915c2f601a1be2a8a06f7937a48b302ec5e158ea07f7883eaf9c7387e7ab43935e2057b31039d0f345cd05762c910e175b2e4bee653231351377753f72ef3141c1b3e9bab1da1190e76626b18e16d7711e2cef1e5df97ff40e625b40c17a957a123d814bff2c06c7f7b4c2b5c9d964bb69ce854b108d8d067e67dbba92c4234abbbe4d422b109d33a1ae65ebbf43a442743edb8f3654cbfb70cb182fd3bfec5ffab2f7326b427a14bf348dc920f2e37c2243d9985bdb27d93e09c21dd1d668f06caa106ae174d45f6b74f33a8b9468e2f241d83c2038174248ec7585ec19dbd5afed483dfb0ddcfe7f97abd9b494115de3b74619725be385ee30e19e3a3463ac344acc8c4e7bfd91e0df1951b6def0f5849b1faf27fd62019493d6747de23cfbd3948fc7755ddd956067489030aba4d65cb3f84b4f6a2f45a2d0af6af3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19295);
 script_version("1.22");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2005-2196");
 script_bugtraq_id(14321);

 script_name(english:"Airport < 4.2");
 script_summary(english:"Check for the version of Mac OS X");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X which contains an
Airport driver with an automatic network association vulnerability, that
may cause a computer to connect to potentially malicious networks
without notifying the end-user.");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA23400");
 script_set_attribute(attribute:"solution", value:"Upgrade to Airport 4.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2196");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/25");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");

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

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) exit(0);

cmd = GetBundleVersionCmd(file:"AirPort Admin Utility.app", path:"/Applications/Utilities");

if ( !ereg(pattern:"Mac OS X 10\.(3|4\.[012]([^0-9]|$))", string:os) ) exit(0);

if ( islocalhost() )
{
 buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
}
else
{
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}


if ( buf && ereg(pattern:"^([0-3]\.|4\.[01](\..*)?)", string:buf) ) security_warning(0);
