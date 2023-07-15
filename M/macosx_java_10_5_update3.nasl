#TRUSTED 3dfce50acb92059e4abb76650221a537c11f7a0d7fb083d9bad5f20547832c33452b1c251d0345282762cf61e3f9920feb68e1c62d6f0804c0d7c2f37456de36d38b5db185b1f57dff07e60a77701ae1f09e02dfbbb1568c67ffccabaf1af47d25b431b701ae80012022fda4701dac85971c82ef127ab12ac28cf035d973ceb44ac22080667818c0836273c9cf7d1f6fba218521816af6f6c11282aa1cc55683b0bc90aae0fe012684b4c89c1b7c819784a97804a0863467d2ee676d5b77250337627b8f100ea75e474a32929057d72efcf351f8f1a481043f28bfc172ac8bab4b2e49caddd21f1cb677b99b4dac1a171887a06df0aeab0826249dd266e9aebe5127af9580787c8c7dc95610cede468812bda1560a42039c58c6ee17e8f7e6b08d92c43a9e520687b6dac99e95f2dba66f7c7b4c14e5a95d5ef75d2f79d31f1d5e2065c80e6c23b189e18272a273cd357a23f92b0765f51148075f02a68483879f568c12c460c44e03bbc0dcc95dedb179f7e47752bddb1c350755817d49d33aa2fbc591d0856315135198324a4f03ff5bffcc1acf2358ee241d8e31836931b3739e8ca89616b88fe3624745d2adc6a630baf11029a1e39cb8bfe0d95abc4d1cd1cde94d2757bcdaf829cb55d238922e23f32818391733dce89195e181098289639b9fee430e45cb7f11f35aa73aa303069e8b6c26b412b3834f697b0696b4e9
#TRUST-RSA-SHA256 4791893f1e83036aaaf02699177de1db2c85a664e5a98671300fde140efbccec5fca70f0ccbd9aed066fe166494bcf82436e2789b4a6ba3b64ca158792c96d4fb7f51fa2f5e2a8a49ade3e6775543134aecd68010f16ea32d440002e17b8b4208f165400cfa78ae8a54ab8a25a67408dd7776cfafa2403e4a54f61b3c45acbfc95cee9e0e332b600d72b636083590bf6788d8a6ae03007de900825422fcd82505dbed58df94d11e14d60fabe253426b40594b676d6bea39d15c674d3acafa62a32ff11d8469b4b6d29fd4f5caf5c2ec523e830805c62644be223b2641b7ad8d0b59b6a8137ce5ed34d829b65ce658b8787cdef7c6fbc399668f5059d900e190bc2db61d01d676d357af4fcafccd71b572437fed24a98305efb34c18920baf547f000828ae18e64911297f4fca804d8a3de9a945540cb0487cda829d0cb67991b9e6cc305cab93dcaa4b4f84ac35f7dfd052b9f374d9dd04fd3f8f5eb55a9548631f63d014f4a93343b7b290ccfe550b29932b1f7bd58e9935deba1b4ba2b9d485b32eca2ef5e64ba6eb6d1175ce16cfba0d0f6734e9b0f4401568998a8af33d1d55e397e418fad3ab36a6eb482ef58cef017f83f7538a0dec1ad744a1876c10b14ed42dcfdf6242076f7fff44b0f0bbe8d7cc35c18807f30c49e205e972dfc2dedc22f041b08fbc515cc512fc0e0d7c188bba6a7a8ae4af0aa23693c47f234ba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35686);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5340",
    "CVE-2008-5342",
    "CVE-2008-5343"
  );
  script_bugtraq_id(32892);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 3");
  script_summary(english:"Checks for Java Update 3 on Mac OS X 10.5");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:"
The remote Mac OS X 10.5 host is running a version of Java for Mac OS X
that is missing Update 3. 

The remote version of this software contains several security
vulnerabilities in Java Web Start and the Java Plug-in.  For instance,
they may allow untrusted Java Web Start applications and untrusted Java
applets to obtain elevated privileges.  If an attacker can lure a user
on the affected host into visiting a specially crafted web page with a
malicious Java applet, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3437");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Feb/msg00003.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-5340");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);

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
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.5 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 9\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 12.2.2.
  if (
    ver[0] < 12 ||
    (
      ver[0] == 12 &&
      (
        ver[1] < 2 ||
        (ver[1] == 2 && ver[2] < 2)
      )
    )
  ) security_hole(0);
}
