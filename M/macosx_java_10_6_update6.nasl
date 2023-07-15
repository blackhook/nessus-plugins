#TRUSTED 9384a8e76d3e361331bd03fa681d7e3a772b5216e67ab7502a38111eb1bff59a818b5a9fca27b645a3b764cb6cf9e191a0163041be5ec17dc9afcc67a5a22fb92e217b386617341ec1dbd0cf0a625b0e5770d506146de2924a9fec6727c9bbe1175ff72feb43c90b71e3fc6c8af9ee9509e6bcdf11b5afb2df0ddac9fec1e4bcd9522959fc604abb58d2870057eacf8877b2e88e973d36bc693c1aed99dc23c8095fc62ad81029b0ea963f21a1a32627cb66a5fe499faf1781b5d7db487a669a618bae34c154cc3c47af56d8f93da893b4b8be8b8fef4dc6594ff0a1b5543e9d4657104e74082b4f6e8232205107cf2f6d54f32d617585159c4c859ddec4a365d61bcff9071087e2793e0eec4a84233bb92a0cf9dfcb76ecd38927bb67e197b872d2c26d4a424a786a074d3e9e86c15166286f78a96f0913e11604665aa53819c775e1e2f4f64762a46f238841909c4c700e6aa199b11aaca2384a9f4550a8e733f01108835443798e8f6e650c41cc22b4637a77e5c8f84a33cc941756505e42cd097db8beb8bf3f3d199c30b592cc283df08039bc42d50929f2e4f879d08ca22f269577ef781d5dc66136ecbb4e83cc5bf65ae2f9cc361dfb5a315e86631227a0fbba34c1a1a4a25fd8d8689777db8967adb20a6e79c6f4a64a51008e8d7d3cbebe7cd2382cf645eb21bd71d4790fb38ae2b16533a584dc7a9fa47360a9eb31
#TRUST-RSA-SHA256 03fe19b3dccb1fb03c2ca14388f9c878d5d9f106010f357fbed312f76503827e8d86d1a0ab55780253bf45470f52418d3094a8e5e4c2d43b6e31f5d6027c2d997467fd44ba98e1e8803928053a9d9e5dcad8744c4fad6c37307d501ca54cd9a1aad889f528a77f3012b542fbe72321c50eab3d7cb49f06ffac6ffcfa24250968247dfcadf568c5f8c25d1b77029320b4eb334a9b9c2dc6da6a56fb854aee9887bea876a8f5d465798544e3913e35e35bb6e1ea89651ddf1f9d66c307362abb0e4fbc82d28c7278613bb6217a1973aae394037e781f86e63874850765f2ba935dba5c2298509423f1ad0a202e11c4324b514b9fbb03d20bace0b0849bf3dcdb838ed5d45d714799a0b986cf19f691df797ecc97f6fe74398d9eb750b0eaf9bfb3b9ec6a60b47eb0e3b652194fcde8e752d285f5ab988962c9d20475e481ecac4fcacdd795f78b0771173d245be606f774de6d7ef5603a742ce17af50fecbc0774f687cdeb1434bf06fdeb44585ab71d2d0b77fa2b0a184a1dcefdcf6d7ee8e92e7408f5b091f4b16f0f7d86917e23bbd6acbbfdc2686f50eb5d9de0ca2e5eb149c97cec91dde466003b70806ceb8c6e50c3d0ebc858781e07107b4864a68a4a059a067fa260a7dd75a2fd24c35f8baab6074b335beec213e15e9819e5760c5393a61dfb472f7d1fcc34edaa9f98bbaddcebcf59f7a95a141c461cc5caa719b9e3
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56748);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3545",
    "CVE-2011-3546",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3549",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560",
    "CVE-2011-3561"
  );
  script_bugtraq_id(
    49778,
    50211,
    50216,
    50218,
    50220,
    50223,
    50224,
    50231,
    50234,
    50236,
    50239,
    50242,
    50243,
    50246,
    50250
  );
  script_xref(name:"EDB-ID", value:"18171");
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 6 (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 6, which updates the Java version to
1.6.0_29. It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5045");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520435/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 6, which includes version
13.6.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3554");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

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

fixed_version = "13.6.0";
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
