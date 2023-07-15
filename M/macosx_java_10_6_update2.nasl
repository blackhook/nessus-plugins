#TRUSTED 3cab188490ce5d0ab39bddfb85aefb666a11087d151fad1ffa7012553fbfdab5f7ae6aa02c07c3c7d4ab8727b3d9cb28767246d7ec92c415418a64214c6c72864139faa3eaeccbe50c894e8b2d4d105733391a5c46b4385bf7b5f75b45935aaee3a2aa2b1fd083dacd762d6fca66a16482cd2cfe1ba75889ad0f77ef4885abdaa16d7cc20a8226b381bcf5724a960003fbab3056b26555fd8e76f6d2fe082b3c857abd275d98227674655f4d2ad9272114b0e4e506cb772a473fdc6d4f21e752606bf9c6e05fa2e54036724935f0bacc57a82c78c28de638f59c388689f3aee0ac44c949ea7b0b95be0985e87cc27a7a5f79ad7aace83860e7cc623396628d0d30752c4df4168949f33b3b52f611a85556c51860cca73d9ed243602aa575c320cf106584af4943b0db5609e03cfaa3ed85d3beb1f7e9213598f257ee46b502ee97f3eafea43d18bd435274ea4e13d9b264e8945c6e36ce9675919f836c5980c22b91df9ee552b671764f02f54872b59f5d89eefe5dd27bfd3987b12d62d137ef247ccc4336886aaaff86b4b2c6a4c09e1194da7b4a67654cde02774dd94a024296d48aae72042ace7e19dcc206bc1732f1461cb63bfceba4e6962907b4a880daa7abd0d6351b7497d01705dac2bf36bb40687bcfa13f7d805630f9c99d524c2de0e517f2a9268d1f513248948dfafb48dca5da01aaed4bc55b1b97df57529b68
#TRUST-RSA-SHA256 6a3977d95ac19a85f1aa1e1834449b850245042003cbdeff0bf14d4534d383a5224e6aa3ad5f7067312be7faa9df0bed0bf361b0f81e1a31e684468c1225ab499d7e2cd8e353abdc70fe64d079d64dce901dd0947039ca869fca76a7f7323963a17f4a84611a8455cd9bb6fdb0ffdc0b77bec7389854b63e2f5336a640747d6aa9c2c75a680f3c48e1d21d10f2252d1f9685be7f52264dea6fd6bbd7ae1cf5a8c4f6635b5229f9191e8c31e1abe50d56d2dd030af0e88e2d8bf04ce33fc90e6a3d813dc887af65da3ccecedfc2035596d9f0e42ea25fd0faf9e63c93f1bf436a8076ba0eef76ae4655ecb1942d63d68ab3342805e1a5a5d25268c187ff12055997874366f606b87ba59cfad718d991c423ecb77b4388194b7dcd70e2d46d766de0055f2764540d9a65a0b071314ee22a51587317b73eb1647059ec19474a22795b5ebff68ac897fb9d9280871949c16c19ef21b9e5f215f1c289a89f792290fd14649439d41b46f73880fecb59fb4ab85f192aaee1ef55e05f3ff666d4117d7f51485ff4febc92256f2cd7a37102533e8cbe79f780eded5c9ccca37462ab036c48da88d556b215cf4b498f5ebc4b839f393d2e6db6b29fe6fe3f29361c1da59e869d8d639c5eae86261f5d1495e23a54c2d8b6aafa8ff1d5ee28f87c288920f54b357304b347fd55596e3e58cf1f1d41ce45428dc97355a363294b7d1570bb34
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46674);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-1105",
    "CVE-2009-3555",
    "CVE-2009-3910",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0538",
    "CVE-2010-0539",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0886",
    "CVE-2010-0887"
  );
  script_bugtraq_id(
    34240,
    36935,
    39069,
    39073,
    39078,
    39492,
    40238,
    40240
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 2");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 2.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4171");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/May/msg00001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0887");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

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

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.2.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 2)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.2.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
