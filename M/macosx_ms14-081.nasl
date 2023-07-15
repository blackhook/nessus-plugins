#TRUSTED 87c67eb2236e13934fc0d8132bf7225a25afe1d67405fefc90ad56df21c36866b72d3698a8e4fd33e5f312f202e4bfbb80b990f170f6add3dfe21d04c53cccbb69ff3bae93c720a523b3cb050e6beb930c633ff58ed586593fc92a34394d98616c453ea7de5f20fa55606191c205af928a4de2fce83ecfbf150bf0b874291a38b5aa9b511efff1befeedc5e56f9badb3c2aead58e625dd5214ebe4cc08454595a814930fb0e73ea187fd861dba4303b8cbe8d0291c79a10f1e5738f49141592daae73d4e554529c42ce1e7267d87d28764aac73584b3a8292c0914543359ed3a9e4fe65958d8306140ae9c198c58c7b0d1a50fbc7c733decc52a598ff70033d30ea4798a0145aa3ea6779852c36476300a20d5f5ccc2950de125186103f06589e13045c13b0c5b5247ebb61ca99af07f9eb4dd56720fee72b2812ad15307c34a5d2b388cbf908c533342f6980f93e0f1973cbcfe7c6fcf4d064a5f85a873b1e47a26677f84eaf06f0f96ad56cd735b81f0d4d9f84a66e45fcad25b242dedb3eded70f6eb775c2cbb096ae6502d6a107d37e5f924753b7f761156bad0cd4131e7c171d708a50bbb53b7005b80c226e7b4039b643591706ec252ee69a78e8a45c4078a1198925b081e920def90f90c45c3d99b31a10f7a03f05174b6d300ea4b9424cad9caa2a528c7e6046b8110211480b1fae6bfe5f15c3f47894f49b70e9359
#TRUST-RSA-SHA256 2293566daaf728c766cd44bae57d20ebad189c646589ad852a1604464c0c46c1e69209b35fc95123c26476cf4930120a5314561c87fd5a3e6887641fff0551e3aa966dec70954142312672448d08fa02de9462de0d9599abf206c4a16879b83632c07e75e7873d0093796c31dca6bb1769c6540edb533be7dd2560052a8c84e40097a52ea19fdff5aed3d1336bc4710359e413f22e0be20da46dc347f4e6b94bc0495ac1fc6307d36b1f67b080e227f22700acac43e57da0f9373fc25a76e0e882017361f053602799b089a6c6e7faeccb57f2f5aed274e5cde15b0f5d5d36da9c299779cc26c0b7b206688cf36380ead3aa4329b3f92cff0018b18da858795ae5ff6abadf0a51887bd2f2522692f6b9c28b22689615b76349b68058557b282b9f4eb6ea5e51b92c0d8223d5435bd270d527c45e0ddeff71d92da609ca1ef70378c54b25656a46ca7ff482356f8eb023942f09b7f6be1edbe6a92f9b992f4151b49d8eef294b69dd5f6e2f5b7125d118132fdf0b8e8e7ebe8e0aeba4aa5af3f0fe245f482d8c3840e5489b657e6ec1d83cb5f81ee2e05abe2c3caa80f4b0cc484bb99870d74e5ab33d54835ba659a92a66760010af96106737d1a136c528d9104659f28ac635cb0e47e3b8500e7e36d7298d6c83f30ca077112196abe448568ec22d77be390f09add8b01aa85639521a4bd2003a80a50e95663b83b6cb397111
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(79829);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2014-6357");
  script_bugtraq_id(71469);
  script_xref(name:"MSFT", value:"MS14-081");
  script_xref(name:"IAVA", value:"2014-A-0190-S");
  script_xref(name:"MSKB", value:"3018888");

  script_name(english:"MS14-081: Vulnerabilities in Microsoft Word and Microsoft Office Web Apps Could Allow Remote Code Execution (3017301) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by a remote code execution vulnerability due to Microsoft
Word improperly handling objects in memory. A remote attacker can
exploit this vulnerability by convincing a user to open a specially
crafted Office file, resulting in execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.7';
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
