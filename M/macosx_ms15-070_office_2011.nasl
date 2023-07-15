#TRUSTED 09ceba0868632e851873df3bfba04c03577ef5f5c6d1af801fda7c14e98e53589d7cf6001e96a01f3e29e06350ec5a784eb2a4c592e0d31477ddb428939ffa458861c34e97e1cf2210bb42a701a5edcfb70f6661e5edeb3f3013aabde31ac510e795746d4be7fcfe430e3e4eaa0347a569d2779025e505720f076add780ef653ffa4b681507d5a8dde6f5ec27c9d384c5480dba4c7b56ef407eca700bb21c0ccec2bf606a9f57cadf82c264a210fa1902eefabd3d0acc5dfe8b66462d1960c2e8bd75ec12b0a53ac18b81faea2e89843481c34b5024bb8a646ae706318a8f7ca602e5c94393af32dfaf492ba179fdad626c31ee05f13593d09821d89620311f877deb5b711dccbd71d2dc32a01b5502f4768d54a403daf7ff2cb2e5e10f61389384bc103efa6f92623a8af33e67619d15e8349ea72eb209531f5c6a710a7f182064c64f0d1a47aef8c124a0d638f563b3c64f10d57375ad652ea85d6e8c95745de355c02ae38fd9442c07307e4505bacdaa170f0318f276c0be5e9156c4fc0f936021b31ac5647601dbfdb2fbfb53d3dda8762c1538578942ff3ce3f9625cf0488a4770d39d20b8a55e81011c6b0c559b51edc8931ed94e85ab93abfd4348ce1d9ed688a9290f7bfbf2f2b432af55bab82a4970a84fdab173f1beb2208d264c3fd2ca2f66aabdb1f8136fa68e15d22ccb6cae3277bca2ea4e1b97c60cb5cd277
#TRUST-RSA-SHA256 63331f0896b2db4ffc64943201bf7c29bad18bfca187d5e6e8c1b04738e64757c68d52dece6b980f166ab052f194a86d195cddcbc929487f5d429870cb1624153114745743ea4298b50e10fa525956420fb4428845c03e63096bfd042ef48b4abf4bc236acb95a06dfb55b1344badcfece0cafed722c9e6b562ba6d34c32209d82e84fe5abe4f9e01f0f0c67584f6bfcaf25345b93317c397316c58291b523775ebff35894f95b75fe98d8603c21b5a07b740819bd2f7b6ca2b3b34d4226bbd9257d93689087efab24732c7d1b3522c6b12d038e43ee5e4817ab09ae9c9dbe26524fdb06793c141d975a69f4b4a6f98948c0e82b635505ca9d3b880be467d85f5a263622928c175f0174e53c5bf60333be4f4b630355a915b4afb39ae08ee7c0c4792ace382cf288465e12e58d6fce806e7149381b473155f08f1de73e035d295f3a0f2e559cae7a3df6d65135fd2ab3e0c7b485fce60a6912bd2ea855f9bcc2e19f509fc55ca285c73f871a83ee610f17f0b94a20426b8c66a660b7f68c119497d8a3a91efea0f80e2ed57c312c92247afb9644a015e2562156c3ca3ec656e7536955fbc994fc5c031609e68023f934de4a1aaa2fa57658876393c2d752c03d00c7b4020683a376aa13302a10c3f254ecf71c4123223cdf9bf6b69d1ae1c0b38400f76de50f51c2f113bbf55da29cdcafd479642f360859a36fe4a117dfffee
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84740);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2015-2376", "CVE-2015-2379");
  script_xref(name:"MSFT", value:"MS15-070");
  script_xref(name:"IAVA", value:"2015-A-0163-S");
  script_xref(name:"MSKB", value:"3073865");

  script_name(english:"MS15-070: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3072620)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Excel installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file, resulting in the execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-070");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.

Note that Microsoft has re-released the patch to update the version
of Microsoft Office for Mac to version 14.5.3 to address a potential
issue with Microsoft Outlook for Mac. Microsoft recommends that this
update is applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
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

  fixed_version = '14.5.3';
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
