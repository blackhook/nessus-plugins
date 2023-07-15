#TRUSTED 1ec49269c85f05360c44d6c0024ea0726e3c142a8c17dfa864d8b3a73ffada66a7c09458277d4d5d8114cc15d7aef477aeeebcad3242afe557b3c63618ebf4c66bb9bf08af35b623ce69ff554b28e2f6a4171528ba4d863d1bde18bf58f0b08faf9c79d19425964f78e79d88a6029b64981e481c7408804ee468656d0c1d772f14cb6e6471dbb22058961306d1022139ffbe11509cf3b540eb4b445065dba0fba65521ae7dd228ac0618fdded543fc2df44cb446d4a3db7c413a692e22db99a825b3ffdd91d5b4ecc9c3bde4f394e61a3b5e651cb05b38c7f79fe233717577deb3cd50564f3172a864c3e4c7c4cda48d7382fcfe18110c0ac2cdb8123bf2eef90029ca61f10349f75aed37d6154c51b701156b1f403e76d6e1dc9e5ff0b6745171229e1bb804b264471055830eecf851b6d0cc2d7dc24de89361969f05c34af0446b536067abfaada6e3c595ac5d1dfc7e9e0e7aefad6dabb057241a530db814de0cf3b427ace3043517ff3b774bb744105d2dcebcd900e62043bbf665be448fb6bffbdd4e05fb8dc006da4cb1a8dbd18544822d698165d221671b1f38daff9bdf043e3f27e8c8ee3dad1e37ff15ee9cc1dd00b1fe4348d628b5f038079a95be7b0d83624032279f728fb622452e25db0d7eaf5f40bd5d1e63c6d3be37558e1bab0583b8dd2d37cb2ed44cc6c7386c7f59c80a988c1c845e036b04cf5a5e1e6d
#TRUST-RSA-SHA256 23b37777ca66a78e5db20be114271fd490a947e90572d618b578102a135dbd5979cfbb78d89c57f427f3fddf43454dbfbd3be2d8dd16b490878cf4108b2dff49338144df2d3a5bc8c15d571a6e75d82979684726c86a490631ed4e8491c21484160018cc0edf04a08a8aae291d923e6fff96773a5b877ac5098626ef3bab20955977a540045192969bc5ec5b5750cb549b0b48047bb6d1e3c3cfc955a2bb9750ef9120f8246ef34e9a8678a2c52d7d3ef6fa85b7859c0acaa6ce502b02f57574bb60a4096d992d6747c195b8afac2aaec2a805ad987094a6af95b99d00e1bda707d6a7df3bcb51a921a1c82611b84291b0f31d3a43a93001ef71d873f63109daf75f64f302da97c9d19b0cf7db59c48a6649b8a3644fc4180c2ac0f6105f0b24628670af6178d3e4098cb798477d7eb065d33cb48c00ae35c28bc5a257bebcb0db1b09168495c849e7145336f50de9ff48aae1d1d3dfbbd33d7233aef206650c034bcf0d98045ad3cf05561390339ddcd6065717f16222b86c92535307504b984c3c013cd1d747ad277b088ceee79dac2774c59b1f87063e17e38c7e29e05e2a339eb71d5818fa5ffee3f4f38f4af245a2d881d66667b65e569d66d707c2c95e94d32da74e08666dd26601bd28da1ae56c2827dbadd7dfe71995f3a4ad6b67bad69c655f7490da7336039ff4d88b488fe325fdc5a97e4fbe06158a8ac67cce25
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40873);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-2205",
    "CVE-2009-2475",
    "CVE-2009-2476",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2689",
    "CVE-2009-2690",
    "CVE-2009-2722",
    "CVE-2009-2723"
  );
  script_bugtraq_id(35671, 35939, 35942, 35943, 35958);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 5");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 5.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17819"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2723");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

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
  local_var buf, ret;

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");


# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.4.1.
if (
  ver[0] < 12 ||
  (
    ver[0] == 12 &&
    (
      ver[1] < 4 ||
      (ver[1] == 4 && ver[2] < 1)
    )
  )
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.4.1\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
