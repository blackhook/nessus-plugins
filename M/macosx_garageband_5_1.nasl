#TRUSTED 10f53af227f4a28d999a90f039f9e60cdfc8be29a050e75e315b0d68733939d5980b9139c63f8b37f58609a70b99551dcaface24b7446717444e5e919266141388d5378bc4cb2377e2d30bee7bc02a1eed73672e432d880b0d39b83a221260605a622df46bc208cb3f5359f616334a45a75ef3b31da05a16c36260eb128c23a0ca6ee9796c3453b62abc537605b5901369788294985549cb6e7eb75617bbd02c48e613e81d208c2fac050d29efdae4fa0bc0bcd0aef4a39e60c7bc8d26cd5ca729228a1055ae621beb64ff39449e2a0b2725ce22005ea1e7495a41ded3fc59b34a1df764d6ce74b8ad66ab8a9cf2b0ffb921445c86965f6b8330f3546843425c4df44935b4b6b85c3c57ee25147c132c279f3059b3742fc87f89bffa183a12670ba374bcac83c882bd016ca78850c5fb14bb88c5a9ca860aee760645d44cef812ef3257ff30c24d0fedc39d3906c5a44855ac65d73f6fdb84436b3eac1f580a01bd56328f906a3a8a38466d881e03e4d65e7bb683360184117c32bc9a947ef07b1299832d426740c515d9a601fc4cf2443d78927038fddf3368d7e67ca3d775dea6727bc8cdea273df1cb4ae22944a0f3856e30adde343f8f8fd73092abbaf748fe824e6d93eeb19d52156e03665cdc68f96f97486cff9283d0ae002948e897840e6215a7b001fa260052b9883e6f2d862aadd999508ec1f6827b4bb31ae4b9f
#TRUST-RSA-SHA256 9b9b955da95b4a684872fe114a1c96259ec6a8410a2f60030a951ff5933dbbf231bc033235fbc4557fbfc6d14a8204cbd94e1177d7c458ec08991f720d7fba131b69f1c24d54de856483bf439b362749764825e033f375e9b2056f2519dee40f421d64a466a148223f899dfb85e44951cec87a1fe3316a3295725dc19d16dabdae4b36762f9ec2b0fdf9c225d2d5229c8b3cffe07399b2c44664354c5165acb8696f003dfc25df3618e08474a7040fc0f7f4d5cebc1375844a03549d96616bbb1f88de5b7fbc8d26b78b4ce663a68cdfe0c1eab982039261f865a08f324bb21d52ec25cea4b28f6c7bb398fdbef103dcfda9672d540df3f471b1f1dde4fe2839c43dd55b0a9b8cadef91dd17756fed0b4571bdd222d6a25b847292303c54c8c83a1d771b36defef1e5f62e065dd7702323f1480b30679fb33ecfdd4022260bf57686b66f0746a29138e6298d46998ab029f4b6aa3f09a8f2b6b5ec90e8d0a47fb3435c8261b0f37abeefb10bca9614e4d87a062be328798ac9bd4fa70fddac7e6a47c94160a877aa1874df9e0e3b72cccc961ccae557c413ef47c3cda69a0f4668d34e0b3923b1dd6499ef4447f4c2f8de0df3139187411fc81f556f193444e8b4f352e2c071d41e3148ef4a8b16e44ec39721ae168141701e3d177028fb06deac56b612df7d8f48de48af3638aad0b0acade65c2aefbb04511d50479d3260b8
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(40480);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2009-2198");
  script_bugtraq_id(35926);

  script_name(english:"Mac OS X : GarageBand < 5.1");
  script_summary(english:"Checks the version of GarageBand");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of GarageBand that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.5 host is running a version of GarageBand
older than 5.1.  When such versions are opened, Safari's preferences
are changed from the default setting to accept cookies only for the
sites being visited to always except cookies.  This change may allow
third-parties, in particular advertisers, to track a user's browsing
activity."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Aug/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to GarageBand 5.1 or later and check that Safari's preferences
are set as desired."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-2198");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2198");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "KB item 'Host/MacOSX/packages' not found.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "KB item 'Host/uname' not found.");

# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  cmd = GetBundleVersionCmd(file:"GarageBand.app", path:"/Applications", long:FALSE);

  if (islocalhost()) 
    version = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "Can't open an SSH connection.");
    version = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (!strlen(version)) exit(1, "Failed to get the version of GarageBand.");
  version = chomp(version);

  ver = split(version, sep:'.', keep:FALSE);
  #Prevent FPs if shell handler errors get mixed into results
  if(int(ver[0]) == 0 && ver[0] != "0") exit(1, "Failed to get the version of GarageBand.");
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 5.1.
  if (
    ver[0] < 5 ||
    (ver[0] == 5 && ver[1] < 1)
  )
  {
    gs_opt = get_kb_item("global_settings/report_verbosity");
    if (gs_opt && gs_opt != 'Quiet')
    {
      report = 
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : 5.1\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);
  }
  else exit(0, "The remote host is not affected since GarageBand "+version+" is installed.");
}
