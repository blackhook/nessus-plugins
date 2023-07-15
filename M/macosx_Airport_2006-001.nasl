#TRUSTED 7b3ea16c313c0846999deae8a2dbf34d859035ebc1c2b7e419e73344f76188855cab94356b21fa09ede9969d95ee20bac0f9cab9447df3d7ffb4e4fc86a0a591635aa630a9b3da20c829bb07b35dfc52b21c6a2656fa452f31d51478339b2f7b36c40e4d33b7917470eb08a527d0d0c158d481774c37af44b0182f57a02574b4f390970ae5c3b42aeaa12d3398c5ce720c1fa5620415ccd273d6727f6a13c564c9e073b75be4345f2572b67bfab190cd6ced52ac5475070baf96bacf6032d9257a6478c305bc2672849fcb3a4fe41080b37e686bacb718b1fe98d604937f3c100afbe882e53347b865fa0e06611c0289a87a1bb47bbf3760951283a9681c6de40779591918f4d70d5249dea7ca36d093b5fee149fe6f9bce9c367ade35471554c8ceb803182072cfc0d5076ff9a3c7f73012910d28d1a3f45cd43475c0897c14db12ff120d9abbbdee3c42cb53e2247da2fe295ea70c64b21d3360af8fa059c7286fef05e63e7c9774203deeb3bf6f2879ae98d09f4e6474c5820aac2f4eab4af8c761646404cf04dc591703f9d5ceb63f711c43418777573faf0e121a390b6507d410c1101c53d8db909020ca187f62d00ebd440fc0a4b4fff762b72f6b0da7d6591994e1473f86cefec5bf89d942f3708269e7c619b3ac8b08ae67538af2ef6dff084c161dddba9d76aaeb53203518351abe434f8e225b96d5eaa4e04a0d06
#TRUST-RSA-SHA256 612c14cdbb62183bf5f527d2f43993fa5fd35e2bc049f7b052053ba3f4b53910c1e3b75bd43f59d29f6c14222190231eb7d7e2178aed247cb6e348f0549c9fef8ccd3df1dcc2367755febceb2db022248a665fbe2ef7a53add9d1c9c44b853609ccdff7cf5a3afa8d034bc7cb2e30b224e1fcbc1eead8051b847be3a963ea2ebb65a4435bfb24f83fe7d77e5fd372ad3342b2b791b38852ed42e788eb996ae45cb00f0bd8ef8d16e0a91e49805a1e3eb4cd9cd087c62c1fd919d43413a74bc99da00e346311809a26ebdbb042eae1f393ee51266dd1a31c5391f8e055055ed7dd9d1456d257a18d4b23c7493dcf10db9ada44769b9fdc42c29f2b76a978caf0a3141cfaa7d988812ca361a9cef42272d6f45e050004bb74e46d7d0ec521dbbf3a9e648d09238cfd1d5f58c52bef72fc04d3eb2067d73d26dd832669d538079aa2570580d204a7e857df8f8ae2cc091d3ff68b1ea877cc10c05c3659de85f917eb280f44c66d54173be4006cad8185c9b97e1ed2de9331873b6c7fd657b8d667403a79d52aeb663a97ecd9a1c5d13023c4cd21459d97e8b102bc1355e707c0b92a634023cb29b2b06612fa31d546ac3bf01327c6eda58f5ce5328643f0f702748414a7bf0f9d07f6ecfd86366b4de4805d2b1a5e1dcc97de0c934d35d11601a60a6decf8e02d597677e2e6072d301df21a9e8f0bf83a5fab8b949fdb9050a8df9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22418);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2006-3507", "CVE-2006-3508", "CVE-2006-3509");
 script_bugtraq_id(20144);

 script_name(english:"AirPort Update 2006-001 / Security Update 2006-005");
 script_summary(english:"Checks for the version of the Airport drivers");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the AirPort
Wireless card.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security update regarding the drivers of
the AirPort wireless card.

An attacker in the proximity of the target host may exploit this flaw
by sending malformed 802.11 frames to the remote host and cause a
stack overflow resulting in a crash of arbitrary code execution.");
 script_set_attribute(attribute:"solution", value:
"Apple has released a patch for this issue :

http://docs.info.apple.com/article.html?artnum=304420");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3509");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/09/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
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

function vulnerable()
{
 security_hole( port : 0 );
 if ( ! islocalhost() ) ssh_close_connection();
 exit(0);
}

function cmd()
{
 local_var buf;
 local_var ret;

 if ( islocalhost() )
	return pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", _FCT_ANON_ARGS[0]));

 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:_FCT_ANON_ARGS[0]);
 ssh_close_connection();
 return buf;
}


uname = get_kb_item("Host/uname");
if ( "Darwin" >!< uname ) exit(0);


#
# Mac OS X < 10.4.7 is affected
#
if ( uname =~ "Version 8\.[0-6]\." ) vulnerable();

#
# Mac OS X < 10.3.9 is affected
#
if ( uname =~ "Version 7\.[0-8]\." ) vulnerable();



get_build   = "system_profiler SPSoftwareDataType";
has_airport = "system_profiler SPAirPortDataType";
atheros  = GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");
broadcom = GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/");



build = cmd(get_build);
airport = cmd(has_airport);
if ( "Wireless Card Type: AirPort" >!< airport ) exit(0);  # No airport card installed

#
# AirPort Update 2006-001
#	-> Mac OS X 10.4.7 Build 8J2135 and 8J2135a
#
if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J2135a?", string:build) )
{
 atheros_version = cmd(atheros);
 broadcom_version = cmd(broadcom);
 if ( atheros_version =~ "^1\." )
	{
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
	}
 if ( broadcom =~ "^1\." )
	{
	 v = split(broadcom_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 4 ) vulnerable();
	}
}
#
# Mac OS X Security Update 2006-005 (Tiger)
#	-> Mac OS X 10.4.7 build 8J135
#	-> Mac OS X 10.3.9 build 7W98
#
else if ( egrep(pattern:"System Version: Mac OS X 10\.4\.7 \(8J135", string:build) ||
          egrep(pattern:"System Version: Mac OS X 10\.3\.9 ", string:build) )
{
  cmd = GetBundleVersionCmd(file:"/AppleAirPort2.kext", path:"/System/Library/Extensions");
  airport_version = cmd(cmd);
  if ( airport_version =~ "^4\. " )
  {
	 v = split(atheros_version, sep:'.', keep:FALSE);
	 if ( int(v[0]) == 4 && int(v[1]) == 0 && int(v[2]) < 5 ) vulnerable();
  }
}


if ( ! islocalhost() ) ssh_close_connection();
