#TRUSTED 39bac384d12776cdc5bc136d9890e8a1b67244b4fc179a5584f02f7311e8effef9ee6bcb58b46fb9318c90ce60aaecdb37bbf8005878835065c86e2d4f6350b6a7717173f778336a637e7d431fd0c256cdab54c5195a580429ec6eb0ac0f9d3063596ef6c2e2911f0c6c77c997eec10545050fb7d38fd09e9a7ad4cbccbda665d259ae205f16735dad02cf9278606906faa2d1c9446bdb49793831689b4998df13218a901e9bc75eaf69d2a6c22f75e42def7083445d2bb601345dce93ccbf21ce024ca275206c562f86e97717627846b9712abc0ecf151c703238480ce9f60e803eb938bfdee59758d3e2832e9e2502ce7258ce3510978fc3273f981fd1d1b6557e823f1e87f87b64139732c904cc74690fc8be0dba9932ca95e2001260a38877175335b616463d251b40027e8b929e05ada76fe9359061692d5888a5376715fe528cb1166491ee6182f6a785544bea9e4b169dea2ed70cbf6b56f51fd3f584749ceb3f16bd3d1e4c358202a4c954e0ac48613185bd0f2da97acd796cb85c8dbaa463d04bcf93c815a7033dc539c2e418b68f37ec1ff9b52a66836990e9a14125a0b26a48bfa3d127a68cf59de4dcd4ffca905a97f206cc5466a8213782cc16a0fd48b6a78fac117b12d4894d57aa26d1b6b7c4ec352ca63af484821ce3ef7893cfe97e903b1de1878c80f5d4539c06b98267c27cde747f45cdb62d7e583bf3
#TRUST-RSA-SHA256 060039d83cc2b556f0773459dbbb9bae6327f29c4094790fbcefd78bfcee26595cd2c56f1e07f5e7c1d7529884ccf7d18975e87b16c022d3ae434f00276acb0dd36e7dd3e9b96a4339735856b45430aeac4249592f6e50633f6ca8c4ae345b88e8fabf30907a4002c40d1520fc69b7e2ef9e39a9d205781037bf6c28ba4b6630a4ec02852a74dd68c09a825b9c6a9730deee031ee54ef62a891ba7da3e3b7acd34db8f130c749a03b7af0dbe93b371e1f45e61de6c61e6ec598f12f185d412dd702906a6cabb068a43d8f57862d6da65b9f86329e25e2a3e4665875660d03d7c0f938ea4b8a10e6925434b9a098e6d20ce49fcf29049b820d82e15046349f7e5a86e2343190d2f9c748aae3d557eea33523e85ec187fbf9b2bccd5af384f8deb7b2a2937dca9757295a8ac1dd025b02776ea80fb0c2ecd059388532fdb9999132662fc07a08ab17c1f8f9b215519cc6b07121e12e99a8a79da00ada8379768d351b794aced2311bb0e17fcba5abbdce78ebccf0a0d32e8ca0680b17fb9ac60183586e662d9abab289928877188ae8c0cd362f7563c2df11f69c607ee8d991808dfad0a09634c27735b36e562c658a5296b1cdb64e15422b5ffa4da654e9dbfa5df873bc0f19714780e80dcedaf51a1980317a47666e6e7971d2f54a1b1ea7cdcbb32f7eb3d6a3a33033effdbe4850272a383494a0beff098c7921b8442d1be7e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23926);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2006-5681");
 script_bugtraq_id(21672);

 script_name(english:"Mac OS X Security Update 2006-008");
 script_summary(english:"Check for the presence of SecUpdate 2006-008");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2006-008 applied. 

This update fixes a flaw in QuickTime that may allow a rogue website to
obtain the images rendered on the user screen.  By combining this flaw
with Quartz Composer, an attacker may be able to obtain screen shots of
the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304916");
 script_set_attribute(attribute:"solution", value:
"Install the security update 2006-008 :

http://www.apple.com/support/downloads/securityupdate2006008universal.html
http://www.apple.com/support/downloads/securityupdate2006008ppc.html");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-5681");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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

# Look at the exact version of QuartzComposer
cmd = GetBundleVersionCmd(file:"QuartzComposer.component", path:"/System/Library/Quicktime", long:TRUE);

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

set_kb_item(name:"MacOSX/QuickTimeQuartzComposer/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 22 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 22 && int(version[1]) == 1 && int(version[2]) < 3 ) ) security_note( 0 );
