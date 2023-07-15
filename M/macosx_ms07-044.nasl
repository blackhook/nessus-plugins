#TRUSTED 55dc870281e7773aeedf12d3396ea77b3b134a16776f4834ab565f16cfc0f09f8fa49e85817cab5e1bdd91aace80d0a773e8d3dcacf8e932e4846272f908fe35d977b9fb3167e1c7065c7d6e5c226ecdf0298f53c51c5556f934c50e48d1c601b4e60b8f056478a0515886f0838c10aca9384408cb471ebc4de208a154b9b0454c647d9121f262f661a9788b18599d35150b3123488d9a894eb7ab5728f67c2af2d6a773b59d27b539ecbb90dbc3d7373bf9b88bbcb1eb0124ecdef7ac720a9a2bd3d9dcd3fedbdbc296ec1857d820a1cf3928629dc326742b520fb7cecfdc625a6bd4eebba61882dae7103d9ef777c1def27f77342531ac4a9f61db1f3221f32606d70ea331dc8ea0dde0322456c3742c3762cb83f9021a27670a698b4c932ac0eb4a9c60117f38a29b4c84b8b5ff25b83e8a052209d064b8b029cb3c6c1e5475165ab04ce1f2167e235f6a5a825fee7092b6a986d7e69dd83b3e8e1d8705efe35d770580ab2899f5969bb658500c121e2af1438ae92d1a9b97e1e51b4645184f0ba7da7641ab39a71eaae81547b5848a09ba5c466e56bb94ea37fda1238d5f6e33d049abde4bd5186c256a3e9a15e4358fb18b953029aa20738e72153977a508cef00d53a85175a6d7dd79e5c8c5be155afe46c5fbf80b4f96646bb2bdf90745bb58953ac2fd895b854666b3deab62fbfac21b9d566630c3f9ee6499fca332
#TRUST-RSA-SHA256 a10d336486fabaa3d8ac86b2e32991b24974fb010b275ba1d092b3416617e54259acbf3ca7e61956f2315b43e26ab3d022f49791a345e1149f962fd80b8ae166b0055268bf9a75ca6dad5da559dcf601d9781014e66bff7148edcd260c6d58d4c5a96ee1648497d37e7a197ae7cd2b3d0b6c1df3c0d0ec6266ea270b22b0b7a86b63df92907d1454006fc0d9831fe28d010ddc429aebcc9237e88248f88a95b5f4dce2c519abaa8bcc7c07b033acd6b03cd282474563b8a2b085a0389f0d70a86af972a89e30fec20c75ae6b41eadb44cdbb4a363e0b48ae81e43d0e199b251c24c1a32b7c9ef28e7ef5fc4bb57e7de895c53db6dd511ad16aaaa80f11ff2e039f49d4661826ddae43b9d787c9bd106c3bd6b899532cc970d9a7d55218af311a9b53f5a4e0b205312bc41195080535ba2e56d3fe462e75c2a734c31b391ff3dd2cdeee82d68436fc087d4472d0239009e5ef5e1a28a2ab40cdc02e1f6b439bde00de50d714587bd21d0f01b8c326e9096498fa6d9d49c99391aa994c3cb09abf48d7f66667140f5b94316d44c2722db777d48a590d9bcfba0e129965589ae2ad447b98ebc0b90ab7d4c0efe62493ab60f91fa1f3717d8cfd0fffe193225194f59211ddfef13cbc9d5efc0541386c3fabcc05e218415dfabcc2f17188f37d89d86d7baca9efc54b43c0e703a4b45459ed79af884bbf6d451431741982a841aaa0
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50053);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2007-2224", "CVE-2007-3890");
  script_bugtraq_id(25280, 25282);
  script_xref(name:"MSFT", value:"MS07-043");
  script_xref(name:"MSFT", value:"MS07-044");
  script_xref(name:"MSKB", value:"921503");
  script_xref(name:"MSKB", value:"940965");

  script_name(english:"MS07-043 / MS07-044: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (921503 / 940965) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file or viewing a specially crafted web page,
these issues could be leveraged to execute arbitrary code subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-043");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-044");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3890");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
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

  fixed_version = '11.3.7';
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
