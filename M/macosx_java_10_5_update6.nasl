#TRUSTED 31122456c75dc9ef539e39e6721743808819b21789856b58544c609a05573b90e3f99ed2be9a6f5b8ee9d08abae7bd8b0c96a01d4d1b436ec83360d8f4ec07dea3d1b8eae288ec9e15c6bea73eabff4287903aa37a1b0da5983e98e01af730cc1eca2717c32695ba57b01a582c23407dd9664d185ae6e6fa173a14454069d8157ac84bc2ba998f9506ad866d7a9fe4ccf1f6c2c1d7498348abff76ca75ef60d438a91c46425e2b4ebb31b6674af8de652be8fefe24a6d43e71d358a53fd0b0b82d6c854023a6397b1f21065e374a6b09915e6373bcf25ffcbed2b9a20592ed3d56030b80a16ec402bd1a51095bdea121d9e485abc86329e2c4e8c05e0b72d33ef6f5b8f44f78a89fb0fa0a31b4bf0c8ee31a7a3e7262511875e32135b75f000b93a7cb984d906c64fb97a291844a9c701ca1ac984488bf2b2e93012eca11f0c54cf6daf5ebeb938f51ce01979cdc13f4e180c7706e2ce89eddfffe0d321781426282786c76f86f36abd6ad0e7762ba3312df4c77db0ad3624a47f85b0efc4c0ccbbf641690bee90163ebe5609614bcc6717e218eeba55c9378d96a14cf15063e38781e1cb4e180b8143e663dcd5baa99dc538e8896cfd49554c13759cd698e350734692e689d1161dc78355cb56cca9f8ddc10b1103799264a3c56f5f3a1b816d62e7b6dad001f0bbb28643a2a584bf57261e4f596b3e87d50525514f8b97bf3
#TRUST-RSA-SHA256 a0a57d1dda8fa02eb346a73387859bf711c4d8d840ced89c11d0c3727f41633609cc8d8f514b936b4a904ca175b098605b85a5958eb1b870e0005d45532101474cda3d336b5584e1d9ae68abdf89ea57d57fbdb9c4b8320f060940301b98f121cee427d336932192768718212d1099597c80299a6a2bc860f507279b255466370477b29259de83ab819f447ff6ebc0df51424205fa5da026db43cbf4d810b006d9e87251958e87abcc7700bed73cd8f139515d1b66142253eef4cea76960f99dd65f245044c32573af9fbe9f4b8727269150ff95a9f2d896f7e5e17d5b11f35c6b37231cd6748c180c944ac44957d4870ddb9b9bd8e2ae8f41c53a74f9d1d2ef029b3a391b572371150d9a8c3455d901f6bcf8272411c32ab77b669dbf924dd4988e04dbf9da83661a304e551f321647db0363c3bbc295ec9400fff509c5941d42774d7aa3ce937ceb443c22b1514cc2f3a610dd3c86bf2ce57752c5691e3b338b1ff53a6ddab50fdbdb461bc55d651b471a22e6f531336bda93bbdc9463e7dcbfb2c772fc2d9420442bf4c54f584380dc4c03beebdbd02539120f51ff4d46572d61b69d6f89da48a5f448d999ff0edd083c122c8ed12fdfd5724ac9ec8b6d882ba81fe5ceb0e91b48afa0e0f86acf25555f495b9cdba576efdf56f8859d56624b63f9bd66b86da1fefa82284d7b0a3f75afde98281a8841725e417750a60d80
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43002);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-2843",
    "CVE-2009-3728",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3877",
    "CVE-2009-3884"
  );
  script_bugtraq_id(36881, 37206);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 6");
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
10.5 that is missing Update 6.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Dec/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18433"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3874");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

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

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

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

# Fixed in version 12.5.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 5)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.5.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
