#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104351);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-3157",
    "CVE-2017-9806",
    "CVE-2017-12607",
    "CVE-2017-12608"
  );
  script_bugtraq_id(96402, 101585);

  script_name(english:"Apache OpenOffice < 4.1.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache OpenOffice installed on the remote host is a
version prior to 4.1.4. It is, therefore, affected by multiple 
Out-of-Bounds vulnerabilities and a file disclosure vulnerability in Calc/Writer.");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2017-3157.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2017-9806.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2017-12607.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/cves/CVE-2017-12608.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openoffice.org/security/bulletin.html");
  # https://cwiki.apache.org/confluence/display/OOOUSERS/AOO+4.1.4+Release+Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcb889e1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache OpenOffice version 4.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9806");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
# Version 4.1.4 is build 9788
if (buildid < 9788)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.1.4 (build 9788)' +
      '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui + " " + path);
