#TRUSTED 23179dea57f3920efcfaae46efe29a38cd903fbee5c24ab3bcab811227a6b9219256182b55f6f1e9722f7df66042699db866e3baacab5876278109766f7d36818d0c74127ed6e662621ddc9230f3ea022cd0049b6b2e24ea9c80eaafa7d80e67094cf1a2b00c70a7a929c996b0347c3e8349fc94c566f86144f770bab03a63c6feb117164e19c7942fdfc59abb560e436ba6a036b2b1763c5ca3ed54eb208fd023127cd852b58c68e00869985d9416ad30a43d516494d8ef324c00c7ed77a179661d41b21c398eb0a04497b0c623defa2ef9c0b0948dbed2d3eac192124131be7d1bafd561d090893c4cde3c36949d9ad96248efe1538ff0eb5086c98532046b0f798f2b30304595a61fa64f96e8467b4cd5701f60be69e4fff9ce1c24a719bc66fa98a4a79ba462be110a185b257b59d9e6f065d816ba34d117726764fd60352e4e0de17d61e665a8539205b6ab48d0750d050f0b8e31fb62e9b301af0072c2c5373c9db64557db881c6ff1f5e889df52f0c6ac05438ba67ce9781c46d7266f211dfbacac9e6e028ebf61eb1e6dfa0b24bba89e3258c78926a4f30da84c6adb8821d5672c4828b3fbe482c79247db4cde8413e506139f39320d536f91d7acdf1f9e7ae4fed973200133abd174092b69bf389c94b7dc051844bc73fc3a26d15fede29178ec119eeb9c05cee1f2822067788a7f3b611321875bb38ca1823f5a0e
#TRUST-RSA-SHA256 a8ee1a7da531224384e96493b477ee36bc793e6ae5b7720f686c52c19b4cdd5e3072046e29c671cd892f177cd4ee3b92c805b395d5317b66416b58168469149332390822e71096e93689fc8ea58f0cc2bda79888f73d8c969205bf3b40ff5c28f40418bc9db8cfff914557f5485055fd0fbb3611c821981917604e20104f34c0be26f855cbe1d51cc56d519d53b75fb8b4f858c27376e4c041056768a0de4dc5483738e8212dcc9f8288b368accec16354ed2a3d2d7388bbc1c07e8e4b33d644b954d27c7c6d45494c2755a78e506161614eb8c72bf7986cdba789a5cefcdfac99e8c40173192df9dac3bcdd62df99b2ebdb021e14387f02ea3dd43f7f7de09abee096561a345647bdfbfd65bda5ee1bc5c9d9327a051e13e5c5a94ff8b40c03fb35522e98c209c364f202c4a9a3ecb71e7fd14710359235c96a84921ad1a630ec6c426ce470fbee0b8515c9499715b51d0a3d45b0a5ef286856f89ff2e651c01b16de863dbd169ca60a470e7d58a46ffd3245c9591c39998349271890cfdad1bf7e279d3d19a82c3438c409118dd4ff53f88be5f727bc3ed9d9d77742aa9acf02b40b73741ecc4b7224001d52a5ec3a6c01fc403df420c09d2d972072f4e59c5e2d10a4078527f92e2bcfda3a638a49428f965a5585928738faa45c38a3111e750f5617663831855238a808485666e4b597e12d57a309636f8fb0c228e4bef7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24234);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2007-0015");
  script_bugtraq_id(21829);

  script_name(english:"Mac OS X Security Update 2007-001");
  script_summary(english:"Check for the presence of the SecUpdate 2007-001");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.3 or 10.4 which
does not have Security Update 2007-001 applied.

This update fixes a flaw in QuickTime which may allow a rogue website to
execute arbitrary code on the remote host by exploiting an overflow in
the RTSP URL handler.");
  script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=304989");
  # http://www.apple.com/support/downloads/securityupdate2007001universal.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c80700ff");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/support/downloads/securityupdate2007001panther.html");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2007-001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0015");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple QuickTime 7.1.3 RTSP URI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
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

# Look at the exact version of QuickTimeStreaming
cmd = GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime");
buf = exec(cmd:cmd);
set_kb_item(name:"MacOSX/QuickTimeSteaming/Version", value:buf);

version = split(buf, sep:'.', keep:FALSE);

if (( int(version[0]) == 7 && int(version[1]) < 1 ) ||
    ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) < 3 ) ) {
	 security_warning( 0 );
	exit(0);
}
else if ( int(version[0]) == 7 && int(version[1]) == 1 && int(version[2]) == 3 )
{
 cmd = _GetBundleVersionCmd(file:"QuickTimeStreaming.component", path:"/System/Library/Quicktime", label:"SourceVersion");
 buf = exec(cmd:cmd);
 if ( int(buf) < 4650200 ) security_warning(0);
}

