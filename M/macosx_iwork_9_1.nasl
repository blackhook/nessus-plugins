#TRUSTED 70f5bda8c4c5fd8f17bf4fce825e8f2a1954bed925816a502f3609c5f477ccb6a4719b6125bce7cd733fd2f8ccf50d72a567d14f5f8ada214f2d3f0c08e37a8e25a0ffa62433b7d5ab986250ca21d0e7eab09fab815d0938d3d4784458db28b8127fbbeea3915df25b8618a56c814c1121d52abc1e07b0dd858c2c04797a88c8e000dbcdd6c003cf9427a23a5512b5378aec629c074a9b491d857c8071ed7ea13a55c5b1bf12a7c67b5621c743db8bfafa02b3cbe8393d80a84ae92ba6395f8a3b3545598732d856c2ab07e90c4b654a12d7cfa25ddc2d115bd2d35488e937135ddcc17e9303eb55186ee894a2b15fb82b0612d86515171dfae2bc2a22fa7cf39b3c17da8bf1e5697847d730bbbc4ac87a7ea7320c1de4b71cccb00258338ef20e9719ccc5f3fa135457733d579a8ca62ee601c6eb02f3399b387bf765c95908b44da2ceb832cfe9d8d47366ea529d9a21491bb8fc2e3f1b5cfc02e91f5c3a8e0752479192bb031e5b653be4b0c5e96be76efb29a41e5cf4c4e19e4517b3f4c52fbf81898b4a9501f58ace95e2dfd455e16d20da171988dd2331ea44b9363ebe45b7b849df6047501b9a50e0ac99e5f6c5aa340232aa4011602b1a0babf47c0ed3a052905b02d0b0f9fc137a257b0ba68a60ae98e3fe70b2ad52bcac0eecdbd9ee6dd24b0e3849dc509b762ad7ff3479eb0b943b63c6023e2e7017687677b158
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(55693);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2010-3785", "CVE-2010-3786", "CVE-2011-1417");
  script_bugtraq_id(44799, 44812, 46832);

  script_name(english:"Mac OS X : iWork 9.x < 9.1 Multiple Vulnerabilities");
  script_summary(english:"Check the installed version of Numbers");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an office suite that is affected by several vulnerabilities.");

  script_set_attribute(
    attribute:"description",
    value:
"The version of iWork 9.x installed on the remote Mac OS X host is earlier than 9.1. As such, it is potentially
affected by several vulnerabilities :

  - A buffer overflow in iWork's handling of Excel files in
    Numbers may lead to an application crash or arbitrary 
    code execution. (CVE-2010-3785)

  - A memory corruption issue in iWork's handling of Excel 
    files in Numbers may lead to an application crash or 
    arbitrary code execution. (CVE-2010-3786)

  - A memory corruption issue in iWork's handling of 
    Microsoft Word files in Pages may lead to an 
    application crash or arbitrary code execution.
    (CVE-2011-1417)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4830");
  # http://lists.apple.com/archives/security-announce/2011/Jul/msg00003.html 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84d8e8f6");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518976/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the iWork 9.1 Update and verify the installed version of Numbers is 2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3785");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages", "Host/MacOSX/packages/boms");

  exit(0);
}


include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('macosx_func.inc');



if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');


os = get_kb_item('Host/MacOSX/Version');
if (!os) exit(0, 'The host does not appear to be running Mac OS X.');


# Check list of package to ensure that iWork 9.x is installed.
boms = get_kb_item('Host/MacOSX/packages/boms');
packages = get_kb_item('Host/MacOSX/packages');
if (boms)
{
  if ('pkg.iWork09' >!< boms) exit(0, 'iWork 9.x is not installed.');
}
# nb: iWork up to 9.0.5 is available for 10.4 so we need to be sure we
#     identify installs of that. The 9.1 Update does not, though, work on it.
else if (packages)
{
  if (!egrep(pattern:"^iWork ?09", string:packages)) exit(0, 'iWork 9.x is not installed.');
}
if (!boms && !packages) exit(1, 'Failed to list installed packages / boms.');


# Check for the update or a later one.
if (
  boms &&
  egrep(pattern:"^com\.apple\.pkg\.iWork_9[1-9][0-9]*_Update", string:boms)
) exit(0, 'The host has the iWork 9.1 Update or later installed and therefore is not affected.');


# Let's make sure the version of the Numbers app indicates it's affected.
path = '/Applications/iWork \'09/Numbers.app';
plist = path + '/Contents/Info.plist';
cmd =  'cat "' + plist + '" | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, 'Failed to get the version of Numbers.');

version = chomp(version);
if (version !~ "^[0-9]+\.") exit(1, 'The Numbers version does not appear to be numeric (' +version+').');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 2 && ver[1] < 1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path                         : ' + path + 
      '\n  Installed version of Numbers : ' + version + 
      '\n  Fixed version of Numbers     : 2.1\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, 'The host is not affected since Numbers ' + version + ' is installed.');
