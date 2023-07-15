#TRUSTED 0f6b8352fc8ef2bdb764343dfb82e0ddc5beec1b9b757bdc88d76646b7aeefe9ed0105c04682675d2a692513cdc07ae53fbb9d4f650e2a0724a3b47fe0bc0347166f0b0f06529a3c77cf9f6351d9c7ed9683d58e5977cf9fc78a1dd18b99e1afd8753de79705bfb2a011a236e7ff64416f4bf7505abdd3891298729f67abd4ff41366bf3cdbd5c183713f5a4d914d303d2191bf6dc4c6569d3a414bf39b943f557071510ef5a7d5e79fdd31eefdf4eb41e47c1a44bccd1a8c2b0be11ddd5d0f268bbe99e415314267e7aaa9041fea88a97fadb49f18ef04d9207fa05677339bd5af88ac5d2884e2a38739daed916c4a5769ee67991cd963cf6bac7216af0791c35af723ca276d175ac345e9642fbc4299b44e33cd888d8f6bf502e23b31248a236a5e03012e6bf658a7d0c23801ec0816c8d5752aae2946a86e0674c14c9dc49105b8fec60597b61b5558e5f67e49d86657b8d293168e8a95496a29afd8e535750232b615fce62df059efb96aa8ddfd13f1390f0652fe6fb627d125e9322bc3e8c17de0c096a0370cf5e1b7392c25f3cb73f35892b47a8a61942fe7ddeb393e669045a6b02dbcb02e8749afd6ca3e3994693c394b568826111d970ef2b099dbc470ee1106b9695bfe592ed333651aa1d9ff89e00e664a4c4050e8351e9b621458eb565137e4d68b096f0af6224278302f19cbde31097b316712b73b087bb38a5
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59463);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id(
    "CVE-2012-0551",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1723",
    "CVE-2012-1724",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    53136,
    53946,
    53947,
    53949,
    53950,
    53951,
    53953,
    53954,
    53958,
    53959,
    53960
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 9");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 9, which updates the Java version to
1.6.0_33.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.

In addition, the Java browser plugin and Java Web Start are
deactivated if they remain unused for 35 days or do not meet the
criteria for minimum safe version.");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 9, which includes version
13.8.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "13.8.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
