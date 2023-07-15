#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101084);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-9948");
  script_bugtraq_id(99281);

  script_name(english:"Skype 7.2.x / 7.35.x / 7.36.x < 7.37 MSFTEDIT.DLL RDP Session Clipboard Handling RCE");
  script_summary(english:"Checks the Skype version.");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging application installed on the remote Windows host
is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote Windows host is 7.2.x,
7.35.x, or 7.36.x prior to 7.37. It is, therefore, affected by a stack
buffer overflow condition in MSFTEDIT.DLL due to improper validation
of images taken from the RDP session clipboard and which are pasted
into the Skype message field when doing screen captures from an RDP
client. An unauthenticated, remote attacker can exploit this to cause
a denial of service condition or potentially the execution of
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vulnerability-lab.com/get_content.php?id=2071");
  # https://www.vulnerability-db.com/?q=articles/2017/05/28/stack-buffer-overflow-zero-day-vulnerability-uncovered-microsoft-skype-v72-v735
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f60cb0f5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype version 7.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9948");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("skype_installed.nbin");
  script_require_keys("installed_sw/Skype");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

appname = 'Skype';

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if (version !~ "^7\.(2|35|36)([^0-9]|$)")
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

fix = '7.37.0.103';

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix + '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
