#TRUSTED 3fdb0dcfc7bb353eac013a6414e78712cb13a2950b1823246137acffb66f9c2e57a084b87b4da1c78145791884d0ae26a771ceaed0c8d4665298be67220250a7e9f7fc37a9ff9ee51f083396ca9aee5277f7892a9fe309fd8a4109b2d332011c022d4c3e9038373fe54ccdc42178e97920ab6bc426e42d508bae41dbab4125ed67381fcf98b8dd81d1aee614fd86873be41defeaaaf0388cbf04a67be46e1f2ec99ef3cea6858ac2ce3f99a6b7a932c14e8c4d9d6fa7d19f542bce39cd27e9e2b54a43f189a32ab4743730328ee775797fa1f7296a0bf95e7cc992d3f2d8336bd74fe87d3c582d9a1635ba17146e957bc97e49c00c038e37f4a54645c313f4b0ac281cdc9c7ad119ec65023ab05303fe1b285f41170c9bdef2ac961444b8c82a37946b2d988f1fa53380f2614000ab5a93bb5d38126643e09ec76ffe8018c20e6baa635b4beabf0b67a217fc97b80b63d0f2695e178355501182357442b6f0ca914ab6c2df173ccb4bdf52274762c22405f2a9bb0b188804378e469a381da52a80dd0b1274ff4a2ee316cd9dbd2b8d34c3d5135d72847b0e08c653b86a8051a2c41ede43bf679629f3e384626d299c47824cdb6e17b69ce45ac2b4d49a68155f2c64de8f224bb127f68fdcac5da7ef3324cfd8c6a6ad0253f198d41a58601ce9e5372e34b20e5dbfa9b6f820a990126cf649ab543e07b599795eae3e16c34d26
#TRUST-RSA-SHA256 2cd2d8c8aa1d642c26ed25bd2d008bd7ebd9c520bbf6644835a78386b45e5da663e9c9598a09585f4f4bfce93a96cc64eccd656d335c37606952bad9e6ec7c8f9543d890792cf34bd80e9a1f94079d977a5b78eb700570cb6537416273d98b811c6fc52ee95511f240f446048c3261a4b5fca1e12e4986898cb53325fe81861faa0a2ac1ffff871bef1db18e8baf3dbbad29e31387e5aed0efd563aeba30c9594da3bfb8f1844447c5b1911983fff4d1bfb29e978394f5a5f699d0972afe7995b2c79ba838ec10974f8f504d518bbd2bf3d4795cf0141cbfdef9b1d8aab313fc29ff5b07cbd4e3b35a62ab7e04d78c594d30c68ba7ac511555331a911840a4141006466e5722172a7d2afca4ef6327786c0244102ac5364b71ad8cae07cc22c91a787999cd8d1a3661041bf152cec6368905f06805a4a771af627d99d352e1e6abb4b90363fb475b89e9e8eaa9064d7a96e416a532cc87e9526a0a6087d85f4879d025d9e0b0e7827a9f2f76543f9d8d57985842bc4f66693fa55eab382f163f9cd1696a1aa520674ea6d262989dfec8e386f086c2e0ecce2b6b0e77ea061da6038022dd956de9245dce8359c9fd4b9c0e1c820d8017f91bc7ac28ebdc441d72f7d60f0ed9dafaf202d10261a0056fcd5cec3af5bb8d26254d48871603273dff2cb19afa77dc06240d6cc1b8a790a092ae24a772a11edd4a8e4ed1f932de2abe
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(83415);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2015-1682");
  script_bugtraq_id(74481);
  script_xref(name:"MSFT", value:"MS15-046");
  script_xref(name:"IAVA", value:"2015-A-0103-S");
  script_xref(name:"MSKB", value:"3048688");

  script_name(english:"MS15-046: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3057181)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Word installed
that is affected by a remote code execution vulnerability due to
improper handling of objects in memory. A remote attacker can exploit
this vulnerability by convincing a user to open a specially crafted
file, resulting in execution of arbitrary code in the context of the
current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.

Note that Microsoft has re-released the patch to update the version
of Microsoft Office for Mac to version 14.5.1 to address a potential
issue with Microsoft Outlook for Mac. Microsoft recommends that this
update is applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_for_mac:2011");
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

  fixed_version = '14.5.0';
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
