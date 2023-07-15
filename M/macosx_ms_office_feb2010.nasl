#TRUSTED a8bd8ce9124e08ddf8f8b97186a24ff760269ace00f6191c3e8aa346fa1a591328ce208ee321cd33474d02538ae3273afdebe0a8533ceb5c775722cd89ede452d738f03fdca280aa3c317d362cbc9c347af17010a7103334e390353ce6a9b4759d930e37d5611bfd56da43b4e73d216d2006fa3cacde3f0911ad98a5b3944a8a52f7aa54de920523b34df04e102355b59fcc89ac91d83ed42dddf52e277fdaff45fe7429f546b854a1899a3a52cec526a5a5eb76171ad10bc648f5ca1405c5945e89bf1e7065c00cfc1d7a96a9a1358ef79835c8b2792110d8287ec52aacbddeebfd6bb8e4b5b36d8f7dbddab0c57599a1ed56c4476278bf4a8f15767ed4bf84bf70fc9a6a14ad744ab343b7144bf8163e7bb6287d5b00316b13246a7315fa420dbed04d010c6aa6230988b1e9bb7d53d31b6efccfc37bb7a534e675b6bc168a701750e3b0369ab6eb566672896a95e0cef841ae4b667db2a15c55937f9807b0e3968d0f0c8e655dc6b1121121e554457a31419df6470a2f876af777599ddb8b814ab82a04908ce31c4daed72bab4572c42991fc2ef8c270ce6fcbe22a939b269e548be05c89b4d1d47fe919f7b7c88a8ba0913d3f7dbee9783b11948a85f366d3485fab2af0bfe8a6a12bda301c6dc076f5173d1974d6d8d51edf7589d807462a6fa0f380fe9f226c9679270fa9fcd3f161313cb259d23a870b149f921aacab
#TRUST-RSA-SHA256 7372bf96df988d1820f663c3ceaa7277881a186d0b5b6f368864c28caa4ab9dcacb8be33e741c309cb3e6ed57a3225365f0bab668517a943cc232bea8f5168853466f4a2e84bf95396afa766492d664e9dd5387f12fbc6440f573b40fb0171bebf7797c006247f7d8a7acecf48fd32a39b0c7a575577bb36e0543e0af6ed14e36d27b3ac25dd9317f535bf6a53a7289585fba6952447b30e7dadbaf00b2119a10a2ce404e460d96d549f428728d36e1270a52cbeadcec86e15389c68135ee212a5926aa6531fa6cb069d6fb8b39a134c5d8827b80b6c1ebfeac779c30162575e453a6f2fe2f6468145de305d7657054d2beca606f80235f18d98588d13a1bba60df028f7f357d99c4fcd82d959b7c8395419c3477f055ca2722eead4d3a3752b85e8b5f225d3099b43a2d75e4ca260334bd7a91554909877363943df35cd0696b049cc5b8d7040989521d0b2e8c70e523e60b53a4b45c8ac9348109b9fe754d6793f81f4cfe3e660bd277341fd05176b68b41c20d249474601ab891e529cb51842e2646bb1c018e5a0f0349e48cdd9825e086d4582696df1ddc68417d95e0658569641eb7564061dbaf6115d569e30dcab0094d4d43839e91638e917b22e84f4bc32936657150a531f0efd564162153764a80c793e929a1ab43d2a450cf5636f59e0e08434ce9a8818ae82bc92008f3d043c3806d969dcf5952f10716ce94116
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50064);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2010-0031", "CVE-2010-0243");
  script_bugtraq_id(38073, 38103);
  script_xref(name:"MSFT", value:"MS10-003");
  script_xref(name:"MSFT", value:"MS10-004");
  script_xref(name:"MSKB", value:"975416");
  script_xref(name:"MSKB", value:"978214");
  script_xref(name:"MSKB", value:"979674");

  script_name(english:"MS10-003 / MS10-004: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (978214 / 975416) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office or PowerPoint file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-003");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-004");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0243");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.5.7';
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
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2004 is not installed.");
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
