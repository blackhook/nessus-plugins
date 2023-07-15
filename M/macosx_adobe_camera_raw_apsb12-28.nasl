#TRUSTED 3dce5f807902cd510e923b8ca040ddacf07e0e1635996ced9140947ee8f2770e469edf55d310d33dc6be04d36e4725cd0faf37afbf16246ccf747ede0066fb78828b859216f954b2ad5d7cf635cb47590ecdf9538f496b53bb9aa8b33ae5db861185a6a9c5afc161c934008bb054e5dfc60ceccd3e5e5fca854771d071d469bc36ad2b2f02b10eb36048b460bf1650a71a59506df317c496eb9948c817427d53bd1aeaf5978483b011fd229e28adea736ee205e0cd2e40d88c7a0c2f514f91a5db05e72db86392cf4506c7d3270eb31aed82b7267961711c722f9493d5ed6ea7b23abe20adc520aa7b6c6a336b6c6464ca9951036fee8c55fe39a444ed059a06e22f5eb47527c3c0c7d17173f04a6ebfeae1d286c20777a2f282e1c10166926588601d65fb8c327d65d29ea5c57283946a87000a2ed4cae5571e767884da03ee3a18a17d640ab4f3a5b09db5311982e7a95c28926d4a3f6354bb9c9c3e4db9752f981a096e2cb18d196468ad203da8dc553a6dd0defeaf37e4d14a25eb74984b9948cc3d7fd77cf48fc68cb8a9ae056d71c2b4f4c2ba6b8f4c253af786b6f87f355bf86af2453dde743680e99aa05075cef93f1b8592cdc282ab7ea37e93f8c7f9405f658a5c90d251b04ba7756f5c8d5aa637dacf1d6fd178325ae075a3529371bd4a26fbbcbb9fb66fd4b250d1f28d2dc9a29033119929e9838b71dc411c53
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69347);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2012-5679", "CVE-2012-5680");
  script_bugtraq_id(56922, 56924);

  script_name(english:"Adobe Camera Raw Plugin Multiple Vulnerabilities (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a software plugin installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Camera Raw plugin installed on the remote host
is affected by the following vulnerabilities :

  - A flaw exists when processing an LZW compressed TIFF
    image that can be exploited to cause a heap-based buffer
    underflow via a specially crafted LZW code within an
    image row strip. (CVE-2012-5679)

  - An integer overflow error exists when allocating memory
    during TIFF image processing that can be exploited to
    cause a heap-based buffer overflow via specially crafted
    image dimensions. (CVE-2012-5680)

These vulnerabilities can be exploited by tricking a user into opening a
specially crafted file and could allow an attacker to execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-31/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-28.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Camera Raw Plug-In 6.7.1 / 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:camera_raw");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "command_builder_init.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("macosx_func.inc");
include("sh_commands_find.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

err = '';
dirs = sh_commands::find('/Library/Application Support/Adobe/Plug-Ins', '-xautofs', '-tenb_fstype_exclusions', '-tenb_path_exclusions', '-name', 'CS[56]', '-mindepth', '1', '-maxdepth', '1', '-type', 'd');
if (dirs[0] == sh_commands::CMD_OK)
{
  dirs = dirs[1];
}
else if (dirs[0] == sh_commands::CMD_TIMEOUT)
{
  err = 'Find command timed out.';
}
else
{
  err = dirs[1];
}

if (info_t == INFO_SSH) ssh_close_connection();

if (!empty_or_null(err)) exit(1, err);

if (empty_or_null(dirs)) audit(AUDIT_NOT_INST, 'Adobe Photoshop Camera Raw');

report = '';

foreach dir (split(dirs, keep:FALSE))
{
  plist = dir + '/File Formats/Camera Raw.plugin/Contents/Info.plist';

  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleVersion | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';

  version = exec_cmd(cmd:cmd);
  if (!isnull(version))
    version = str_replace(find:'f', replace:'.', string:version);

  not_vuln_list = make_list();
  if (!isnull(version) && version =~ '^[0-9\\.]+$')
  {
    if (version =~ "^6(\.|$)" && ver_compare(ver:version, fix:"6.7.1", strict:FALSE) == -1)
      fix = "6.7.1";
    else if (version =~ "^7(\.|$)" && ver_compare(ver:version, fix:"7.3", strict:FALSE) == -1)
      fix = "7.3";

    if (fix != '')
    {
      report += '\n  Path              : ' + dir +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : ' + fix + '\n';
      if (!thorough_tests) break;
    }
    else not_vuln_list = make_list(not_vuln_list, version);
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Adobe Photoshop Camera Raw",
           join(not_vuln_list, sep:'/'));
