#TRUSTED 6fb8162356094cfc1277108d78334fcf2aef31fdd2e2483b24877f090c59447f72b713929bd38a63f32145efe027e32a5920ad3b266d8db7bb72bd002ac2e7e78e316fd2ffb3a7fc5d2103a3e71528f20b8c2be19299d1818aba5dbcea9ac5efaaa633394b2a379a08d2ff0c45d74cb6e6565aaa3f3db372b6e524464bae96967cd6345d4c3665800299e00f671cf72b0bc7cc6c7e4088bab70e6913d42075a96e3ed7eef78c8d666cf396b62f75a4c18ef383459b1e96be3f072aca80336489af6bf99d0dfe271f6fa5b5cac8bbbe6231eb281a86c975742435fb0345a6b27b348ac7ec67b97a25e06c61ade6dae24f0de5c7735b0b4c466ecd3a4575564b3823d337d3f255c5d5a2750c69d54cef0cda2d938320dd1baf4d25e4132af4ea3fd6171360517d46d8b8bd455b5d7d0da1f2cb2df5bc56abe41921394acab44e334ed746c2dc55d3c7c74d9ce78e0319db32b5bef37b940e2e98d2f9307cdf44d8712d00f50d27d53e3f339c517bbbc9dbedd1b8da6be668a04fb4a4c1e09a11831e4e40ed87b5e8f7fd3aeeac3e9bbb3f60b91b95d892f70a25d462339af8b82e4f46f554d8f648a8735a644dde02550cc4e1e44bd7e60c80c831f120528c53770b4ff2edc59deb5765c79e395f5517a823655a9773b47a3ca29e3ed5078d3f1ce85da46b1ee7efd79f144d41534a67ee9e192261588da9999ccecef3e546dd56
#TRUST-RSA-SHA256 963146314bc5cd2bc55f189966f65206853a66b189053ec722449efe77b210a10ca28beb6e4c63ca51fe97e795011b82c87a194d043a7f5425e53faf111d437047d96269373f83300bbc1c38207f1c57b1182bcb1fc1dedfcab2bb61d2d48e33e8992b14289adbb6fc545fa04831037e3a34a160d50aecbce930bc27ee36ae34be8eb301c1cab36112f065cc0d2df049e813c7c0725c7ee821497e4427ef69b5b39eae750264f301632a6b2fae5195149700afd0cd1a3976705a7855e5e325666750ce6d46e12f054ae97f8d5f28f1d740bc90f2068a997519ac47dbad3dad46ae44f442b14a76cc2de76e173c0a2907518b43631cd785e80c0215d1673bbdc23191f01b0ed5a25995d243460600c7ddad6fe6948974ac31fbd4bd56408201fa7926714a0b4f15da065f5bff933b4584a2da024f1f49871611ce4b2c85fbeefc63e441d7da976d49429519db11472151304c312b8153d22050002baff92a2379d31f17a78df98a9fd76fdc1728a5fc4026f78bef75388daca5fbcbc09740f626efe8093d324782d02f83b0b4b8a8645cc81a5d118d2d061edc24269a38d4e6687251ec8aa454f5b760fef47f4e2043d502c546eeaeffe59dfa068c85b3defe0613c1318a2646d8ea0ef7af7b969c8aa88acc75c82d6e0409bea1582f414d9e077543b73b89f64d5135c32532974d99e2af29551a90f5dbeec285ba9d0afdb5ea
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24241);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2006-6292");
 script_bugtraq_id(21383);

 script_name(english:"Mac OS X Airport Update 2007-001");
 script_summary(english:"Check for the presence of the SecUpdate 2007-001");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not have
Airport Update 2007-001 applied.

This update fixes a flaw in the wireless drivers that may allow an
attacker to crash a host by sending a malformed frame.");
 script_set_attribute(attribute:"solution", value:
"Install Airport Update 2007-001 :

http://www.nessus.org/u?0af16cb0");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305031");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-6292");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/30");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/26");

 script_set_attribute(attribute:"plugin_type", value:"local");
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

function exec(cmd)
{
 local_var ret, buf;

 if ( islocalhost() )
  buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
 else
 {
  ret = ssh_open_connection();
  if ( ! ret ) exit(0);
  buf = ssh_cmd(cmd:cmd);
  ssh_close_connection();
 }


 buf = chomp(buf);
 return buf;
}

uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);
if ( ! egrep(pattern:"Darwin.* (8\.)", string:uname) ) exit(0);

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);
if (
  "AirPortExtremeUpdate2007001.pkg" >< packages ||
  "AirPortExtremeUpdate2007002.pkg" >< packages ||
  "AirPortExtremeUpdate2007003.pkg" >< packages ||
  "AirPortExtremeUpdate2007004.pkg" >< packages ||
  "AirPortExtremeUpdate200800" >< packages
) exit(0);

buf = exec(cmd:"system_profiler SPHardwareDataType");
if ( ! buf )exit(0);
if ("Intel Core Duo" >!< buf ) exit(0); # Only Core [1] Duo affected


cmd = _GetBundleVersionCmd(file:"AirPortAtheros5424.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && buf =~ "^[0-9]" && int(buf) < 2214600 ) { security_warning(0); exit(0); }

cmd = _GetBundleVersionCmd(file:"AppleAirPortBrcm4311.kext", path:"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns", label:"SourceVersion");
buf = exec(cmd:cmd);
if ( strlen(buf) && buf =~ "^[0-9]" && int(buf) < 2217601 ) { security_warning(0); exit(0); }
