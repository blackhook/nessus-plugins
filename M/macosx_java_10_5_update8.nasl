#TRUSTED 93a84101fcf190cb3fd1b2e2f63ad5c51137205f908085dfbdad364f4a91913b720810c4723f6b6a98bba88ad03ba31eb28dcf398ddbf830295185f78897cf2866a6c09c82c4cf904de6090af83294ca0ed1cc8d35fe0fa62cb11f70a4bd296ce611b42039708ab3176bc1e8b3930da734f8d0c22dc1546abf3451bf0c9cb712bfe9bb0fdd10971eddff101e65993286b92dfecc0d833e96e5a83b5b526eb9d1f5efc5c41f0dbd273bdb4714616e484ea0e8e02f2ac699dcc1079fa00893ca661e8ff7eb9c123faa6f3b431675ef80079cd5b482722914c50cc1320715f787065236994733dede9d2143e1eb1adcee2fc03f2650c5d4ad35c110555be760ad2f2361b704992f242877a1a41326de0d715f165bbeac3d48d187016c5c72ac6c58375ab4585e1381fda9d975b84f20e950fa30d1cbdab7bc32b6f308ad939638b387c2a343acdd792437e2bcabddad60d50ee35f1e95a5dae572e521e666502788b061ccf4372b8eed365bca91768000a9fc708d4c244ec9b017e95a4988b9b934eb0fefde2cfd085e19bcecf0e3566aeae37781a80f26b3de5bc6533c98daaaf6be5da63f42eb5bc5f44a3321a902eda8c3af9580bf4d17483231c707c3c6033289f7ae136b2b83a679eb3486664eca610e137c2798dce0c977423c81002aa651075e54ccde0ab0aec5159ceaa174d71b7ef6f89dbc666a600477fd194e001268
#TRUST-RSA-SHA256 25f2fcb4a92ab9a4dd4bd37fcbeea54c3bc23ecb2d353c9531798725d2a1c9553cb3441062b0e8f96de71f9970b48cf16d0d420b23050719ba814ace1bc5fc5c77ad798dbbb3b4be3c4bc42661ecda167d664993f678785446047b5553b97e0eac252303ba3aa08d59b6e11bf92b35798a877c0b52c70bd4c9db042e60d901a31b40c874dd6a5967566ffaacd5fdc3787090988b9806497494c96437411337eba364e402f605a8c6459a45381fbb4d631c42853c0b56df87f421997660eb686ac15e9998549bcf593bcba6aeaf7a9841f155ffed36e1412c591547f50ae7d43b945ab1452a30e451e0eed4df6c01f12cbc488cfadee6d1ed6112b2228ff7b908f4db85854845e03f43452df34ec0fc42b4d31a9e42d27944258e555cbe1cd4d13b152a7c3a4f79ee501e8ecbd46ddb3e4ef24fe589b2844ccd9a2ade546cb8e79e765b1b914c1eabb09ca049b8e52104708750cb485580f2e814dbd5481c173aaa3e94a2eff2ee998fe914e1782a92da21b07b3d9f08b1d52f2186be65442daa30d76c19d89331075822ee0e013beb843cdbc1370da82253dd7c055ae7fb8c018aa2750428fbd3bccfed979123a93c711b68ffc2b574afc5b57082267e3be0e99643ad96efb4dbf901b419a221147ebc490c48d481e3276939e23c32a228a52ff3f124ff8812e5861fae057d366c30a757211019f655cccce2d8cf18c1ded68f
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(50072);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-1826",
    "CVE-2010-1827"
  );
  script_bugtraq_id(36935, 40235, 44277, 44279);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 8");
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
10.5 that is missing Update 8.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
or applications to obtain elevated privileges and lead to execution of
arbitrary code with the privileges of the current user outside the
Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Oct/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1321");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

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

# Fixed in version 12.7.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 7)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.7.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
