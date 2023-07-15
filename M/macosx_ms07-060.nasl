#TRUSTED 3dc301bc9e1be3d9a34c5c0164349acb5bcab4e23348d5d05156a5033391413eaa5066dbba2ae75bbeb685b3ecc12b7aaf43d931b010dfb5038ea98f1d0177e2dc40bf94ba2352d626394676b1afcd29c7f70265fbb5debeefb8527a179aa8258628d2b2e153cd27b469778a5695363cf506395799fe570ca3f81cd5da60b9f8e9faec8bb35f912d301f3f07cea1cccbb048004270f3c99add78b68d5a15843f6653241005c00e8fc3edfae9f91bf6d723091876bc38c9d1839fdf2b0844c398a91c341efbf9250611e557a74f02ecb81d6e45ba259a5003f40724566cffef53d4ec084a4fc7b71b2841a4a17ffdaaa938d8fe54f0fecb58e613aca2929438c7e5e366147e16d76bf697c18f827759b41daeef9f37b71d7735653a13f3c47b09c62d69c84d0c5ea30d3b759950f3e475eacc9f71bbf824f88f4ab9cfeff24bc848b0b540bf06310fa6e231f79c196d651cd72250029a0b53f4697525622f7fbf64fe89951fe4648249602333cf45a6bfacb09c2bbfa18614168299492c1e8b2dbb996cf8e2685bba28cef0651bde68505054dfafe884001152630708ae09ccdf806164d3a055f73038c8689b712414b3cd7670731f2bbb5b32daec8830d92bf24b181fc561f6e97f99d14fe16b72a91b5dd571b3734612e83b6dd30c0585b27d2ee4476eb5de26ddae5f6e59607788ae1c5993d757cb0ff18e7b82388549a70e
#TRUST-RSA-SHA256 80d4b35e648cf7400019be9fb256cac77726877c1507615be7cbdf8a199897abe18eb50d96b7ebf2adc903f0283526b0b45df233ec18bf0b38afe56a4eebf40a8b59040efae16f7ca6e7a1a82164d507c99a1e83186dd1bc0ef60ebb56efb897ef7a81e522d5b1d2dd0ffccb4d10fff3c3760f39e7a0cabb92637247501df15c676260afaeb5639d1ad017e9bb9d5cc45571809b79dda64ca4c426855cfe423b7471b771805a379f6663be4ea6c49e6c1e2085c4ac3b20d51d4bbb103962150c7185d5f551c450499319bd2117e4495e971e22a17d4929dec9c86397f537d0c365a34c2fdd18da96e3a83625e094bcec5e190d850aeabcac5b959db063f4097988055bb74f41c8da962c28229ef535526ff31f105dd8e1fa987be4c5a59861df2d3d8fece98a14cc944a667929a85f5032f0fa504013ceafaa0a54fbcae3325dd7b741a4a425d37e1332261ec8ffe7174c5512384c8fbbc5ad9a0f841aa1e346951db0cfce19f547042e4cb17a1d0cffefcf6ece67ac3877ebaf506127a22b6eb5ce6038b515e13b4ff25ec16d01c29f3bddc85edadfe3392fe41631734795c09278de8d76ccfe310f1535d546fae8d752bac902623b8226771a2c644ff60d93a8c2f5b34dfc85c3aac61173dd3d9419812e5938e4c87c4bfddb04b777e3901173b999efa7ce1753727bbd37cc80ec3b79b25ddd98ecd38142093464e067eaef
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50054);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2007-3899");
  script_bugtraq_id(25906);
  script_xref(name:"MSFT", value:"MS07-060");
  script_xref(name:"MSKB", value:"942695");

  script_name(english:"MS07-060: Vulnerability in Microsoft Word Could Allow Remote Code Execution (942695) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by a memory corruption vulnerability.

If an attacker can trick a user on the affected host into opening a
specially crafted Word file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-060");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3899");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
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
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

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

  fixed_version = '11.3.8';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office 2004 for Mac is not installed.");
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
