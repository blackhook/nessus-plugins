#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122033);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id("CVE-2018-11790");
  script_bugtraq_id(106803);
  script_xref(name:"IAVA", value:"2019-A-0040-S");

  script_name(english:"Apache OpenOffice < 4.1.6 Virtual Table Arithmetic Overflow");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a
version prior to 4.1.6. It is, therefore, affected by an arithmetic
overflow flaw related to handling virtual tables. This error could
allow code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2018-11790.html");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.6+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c28b446");
  script_set_attribute(attribute:"see_also", value:"https://ssd-disclosure.com/index.php/archives/3758");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("installed_sw/OpenOffice");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name   = "OpenOffice";


install    = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
build      = install['version'];
path       = install['path'];
version_ui = install['display_version'];

matches = pregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (empty_or_null(matches)) audit(AUDIT_VER_FAIL, app_name);

buildid = int(matches[2]);
# Version 4.1.6 is build 9790
if (buildid < 9790)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.1.6 (build 9790)' +
      '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui + " " + path);
