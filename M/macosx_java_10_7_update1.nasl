#TRUSTED 88fb88f97b2032d8c8805d28544a9ee74f1e0203ee7d9300ba62ba42e6f9c88c8bd940a5a53ae085362eee0b0bfdef925fc0199d809ae6210f1e56f0e9643fdedc2550f672ae46017a0760b35fea9bab9894f1cdb410f6cf3c8404ce8874d317b31d34d624c7f71a63bab1399bdbaff584bc04ed1c8afed9b9576de8c794fbceba11996bb254d4a267f41ad174a9336e4d17bba8ebf694ce72aa49b62e9e75ed8a68e7dfe85cf8b3fc057625b93fce2ab27a1289ab71cf1d70f19cb50de6b644bb5ba9b36cb10513876d078c370a14e66ead546d960d595eb4f6b219fc80242368404931ba08fd83c39f03bfdd6ebc1bdf73a9d8fa85158b8abf8f5bae4bc21ed90042a069d05380d70948258df7362b8c8708dafb4f5731b700e513c73d876e1ab55f648d69a5e20af8e8dbfee3a24dcf5aeeb888c49218977f88924f9a8fff0c1caee7b0b2ab44c7ff23c109e934d003bbd223bacbc72cc41b04bb2e68493ffa056455d87393af85a0e53d62e69285c7bd8d1db3acb33a6dd7f6c7bd800c7b61684aea334ab4e47137999b7cc1cd008e4c24afee97d0a39817def102781e82a5c574760a9a1e08d4d8c19c4e06aef6dc5c26d3b4a5698142b41e0857053274fa071b55247e51514c4ea72dc730349ea1c47b27bc9f36f620a90bd4ed0e22d329fae0b89fc564cd4b4fe24936e76b76a03acb272e94ec0c56b3e3277c91a73c
#TRUST-RSA-SHA256 291b536cf024074858784e899b00e3cd36384dc61d2150643950dfc6ede98a17aae4c6464fd00ca5d830ed3dccccdad74ed20fd0cfbcabe921b8fb93c3db423a1cb3a688312014c71803e3315b16589612fa0a0274fad1b3d5788f87219fd27272a65e054ff987f4f28c310942ec01d80c62a341f6cc1ed19b89607f75ac31c61733ccd3d657c98e420ad31bebde21087056d99dea013547a483e431bf3373f57479ad9e7e312e204449f860a3a6b48059899971f450d983a74ff09397eb55dc08699c0de5d3cccf70bbabbf7bfbe72e0564ef759317e5d427495d4b4548d5229c26caf58d914108b39c465a0559b85ec07f68f43ef8a5cb249028eb71635b295788b01abf33da578def77097f1bcb8c0a2e4b78088b727a8a131b958d3287629785b4e8912cdcf7b59ca5d086282e4cfd66831148bd2d6ad3a55c868113b1328bd3b7582ad82096917c39fa8bc3ef929ae386be3c3858702c870419091be910aab5f05c8b6d663eeb5732808765ed2a8075c9ba6ead79494e814c2aa26172263473b298b926b77e491d4c4c22b74588ddc36cf191ac903eb3dfda0ceb9bda7126086e91a44a7ecc2c840908c1e9ae0cd22b8d47d0fe405bf34303d770ccc8a58d7ddbccd665aaa2586e5037303249250b08aa2a1ea2de97993427776ea62733a60ca5afa0bf4125587a88937292ca76a3171afa8be7673ab01c75de45474ab0
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56749);
  script_version("1.21");
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.7 Update 1 (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.7 that is missing Update 1, which updates the Java version to
1.6.0_29. It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5045");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520435/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.7 Update 1, which includes version
14.1.0 of the JavaVM Framework.");
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
if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

cmd = 'ls /System/Library/Java';
ls = exec_cmd(cmd:cmd);
if ( 'JavaVirtualMachines' >!< ls ) exit(0, "Java is not installed on the remote host");

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

fixed_version = "14.1.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.7 and has JavaVM Framework version "+version+".");
