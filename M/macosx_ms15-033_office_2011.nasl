#TRUSTED 00d106fd5c3295b3b64af3155059c66fddc66de0312c9e11cabcb7d2ceb81f8079d864eb5cdff886ba13ac2757a721e87d85919ff1a56e79a71557f7200ae973840ed0e2e88f17624002c104d7baeef75f1a73184fbbc44e243c6e01e2a982ed72af9ed94d0932a87a34aac8f869295d3cc1fe113257077793a2d3b0b5bbda4d1ecc0c42cb660838f905c1cecc82cb73dd034ff105748bafdba337f0e4ff7469606a42ae6c47c1c8b10eb798619f4dd3b645c18583d1d8afe503225fd07c2b97a6b39c49e4c111aa23b29fd3b36ef02fd3ec968eb04e9032805b08ef42f369133b6a6552d4a9a6d7742d1f939654c84113a170678685611c81a30aed16ba92802c185f9ce93ef878602b4a070ea42c367668866d194af071b46f8a6803652c9a2bd065101fa970fbd4ce6f8417a13854a6f43370c09b173a6d8d4c1874464b33e6ecdadf104721af8866d6d65625427942866bd945a73ad449d019818460b6c51b5a9139bc038b6d7ab2a17c34bf98593015ec12149f636e20801bece5eb77d8a9f51cebadecf16b4616bd9a568fe2cc15856d0af1d4bed0aea026aa98b1d2b9154e2306aea6b78f8dc13913b55c426fdde160893035b85e333839e04130d0875372753eb51d2cfe7e94dc5e22c393ab3dad69612a2d10db8b12e64129eaf61edaef5b42ea4f6f598bef6159289c6826c340ecfa44001f5e1973046c02f6ca40
#TRUST-RSA-SHA256 8f4d140ced508fac3280f896ee004b3c593a8e3d11ca6755d5107d59a3cea9ba7c4ccb14f6152fe5d2c1cbf94984e0bb935f13dcd013e1ad5dd686f1a6b61a549f5b8fa20ba2fa09bf983bab8de7dbcfb11f7b74b759a7a01e15228f6bbb5a286a2ffa94accd359f229f26b7e814174cd468da1cc3c976e350567f9d199109ef96bbac664752f2c53a09b12ac553949273a862049959a86868a1bfdf1e29e77154977ab1b6bd8327d98e0ff6261aa4ae086631f4f3233e6654487222d63f4b2584361258b14cc98a0a4460d49ed0fa19393b3f3e00f6f94e4007b1c88601bba823c85c677403fb9605d207acef54b92adba9b3944b0874b5eb3e14bbf694cc427113b69472692f3386bfaa2c52bf003153b6eea9424c028165dfa7aeb00e2ef0180317ba2dd2daeef47101b18173a6d4bf9276798ffc8ab56fd3c20146391921c818405944945e23eb1046f32391f40fbb8597da5a6438b0f86109fad810f57ff6b0b7ba7b83d73942a0886a33a2b47ec111d86259c33acb1aef64c896aaa94ded78858df1769137df793d76108486327af02f923495926e299c7ef447206ac0c32142be2df948afaf109778dd0392a69d4ebc19e30dcee8337a6ff674f172b69527d474612d3f469592be605d6f9632229e95e446d20ff75d2ec1df7a64fa82b9ee474719c4a0d268352c87df2a8360f74ac8cd3fbe50802cc39d4b2dbc5ec4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82767);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2015-1639", "CVE-2015-1641");
  script_bugtraq_id(73991, 73995);
  script_xref(name:"MSFT", value:"MS15-033");
  script_xref(name:"IAVA", value:"2015-A-0090-S");
  script_xref(name:"MSKB", value:"3051737");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"MS15-033: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3048019)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Word installed
that is affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper sanitization of HTML strings. A remote attacker
    can exploit this issue by convincing a user to open a
    file or visit a website containing specially crafted
    content, resulting in execution of arbitrary code in the
    context of the current user. (CVE-2015-1639)

  - A remote code execution vulnerability exists due to
    improper handling rich text format files in memory. A
    remote attacker can exploit this vulnerability by
    convincing a user to open a specially crafted file using
    the affected software, resulting in execution of
    arbitrary code in the context of the current user.
    (CVE-2015-1641)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:outlook_for_mac_for_office_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.4.9';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

# Report findings.
if (info)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
