#TRUSTED 0613cacb77a1c26de9466aac31fcf2ef374763e2716095574ef0c2ce6d9d17c09516e785ec6ee7f81d139fc17957b79639eef7f24b15be6366199a4eacba4d3ce86abef24cac3e98c30e60c65489f4c204c7092c82a9e410e519f07799af2b4bf0177f968a03896a3403c2456f40f2a1224aaaf55ac146daabc4f2253fbb617b7fd554cf3d5fec9c84b4422d150cb6c187f0e0a1de429b29d0db1896fca26a0688836448f30f932cad793769ca5905b6c93339f9af66b7877c890a3c8471a6193143dc71876786cbb53edd0433dd5ae8846f2dc89dfd60d6c4f962aaff8ddc3989cb47807777f259b2e79d2a4561be7b9e5bbc5a7ad1f843fd7378a7e8a98a46c8295c86a9d0e2f48f68a345b6ac9e49e403ea1f208175580b9c440f0e5e1cad6b544b137e8bae26b3f2c8ba00ecf662fd1222239ec0c78b71d4bb949f648127edc02c6bd69ebeba6ebaf7fba23ff0ecb03a2553d2a54e7c10a68593df4ade82b014ea653d8a0767cef9381f413d517ca9b9e7eb755ab25f18cb41ee37b160c4baf16f080321e0dd562d9b1ac54e75e903fb993a906bc21180d63fdfc211d2903d50c58a469061f56206226d42a2217149e2db79d3dbc43a620fdc95cd68ada63328b2a265a3f93e626ef474efc26ca9df683eb28acf5c415e7ec9d2fe68842dc108f2ddbf2ca2d0f11f05bdfea428e9c247fb07da896053dd930245a37bf5ae
#TRUST-RSA-SHA256 40dc3721dc7f91d725b229441893f405c7c139aed09c42212226f298e507d5f1ee7be73020a69bcf80cd93a02ba92ce12830530c84441c1c4fb6316b8d5cca17c3cca0902905f106b89bde65732e9912c2e0e3411e5348e5e3f6d5f7cd1a276f9e6800a21f8270cfef979c1f6b580a5f1183945f4d809e966a1b43c76c916c81d1d049f1094a110d98a52549c7744258763e2e0e327bca1d77ada28d45c8f15aa2cb0e8a74f55c11f48e921d297fc4308367e8a7af921601b1796866c88aaa6823757e4395b990bee8829e5961bcd31633aa7784b5762b44e66f2cf1d6d554def131c281756dffb29f9f343c25f2b163fd8ee4eb9ce4975cc0e1b24d69b54d7c368ec0c5a982ea0f28ab8f8625d681afd579a98b493c9b2260136a69020a7bb2d786d341ce0b7d6e72e016967e223ddf6eebf40d0f26d3b33839058ee16d29d15a7c507232682b10ae8f69acca7935014e29942047c44e728d2900ce6117d6d5094298f069da2870caa643ba0f7b136d710843a72bcda7a448c5ebd7d917cbeb7430d66244794877160f602c593fea6e443eeb8343531aa647fe3407f4e3950846494b2a3560266ffe67218367205df453f744f1daeee120d98f05f9407795a02da36a34e08916a9bc773a3aae83c460f93495d3aee1776aedb66f50abf7e65bdfa84711696eb448db1fc527bbaf02f5edf07ef912729d2c219e0ca83ad1bd12
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46673);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id(
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
    36935,
    39069,
    39073,
    39078,
    40238,
    40240
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 7");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 7.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4170");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/May/msg00002.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.5 Update 7 or later.");
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

# Fixed in version 12.6.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 6)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.6.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
