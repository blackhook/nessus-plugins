#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80078);
  script_version("1.10");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id("CVE-2014-3524", "CVE-2014-3575");
  script_bugtraq_id(69351, 69354);

  script_name(english:"LibreOffice 4.x < 4.2.6-secfix (4.2.6.3) Multiple Vulnerabilities");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice is installed on the remote Windows host that
is 4.x prior to 4.2.6-secfix (4.2.6.3). It is, therefore, affected by
the following vulnerabilities :

  - An input-validation error exists related to handling
    Calc spreadsheets that allows arbitrary command
    execution. (CVE-2014-3524)

  - An input-validation error exists related to 'Update
    Links' prompt handling that allows information
    disclosure via improperly included OLE2 previews.
    (CVE-2014-3575)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 4.2.6-secfix (4.2.6.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2014-3524/");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2014-3575/");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "LibreOffice";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
version_ui = install['display_version'];
path       = install['path'];

if (
  # 4.x < 4.2.0
  version =~ "^4\.[01]($|[^0-9])" ||
  # 4.2.x < 4.2.6
  version =~ "^4\.2\.[0-5]($|[^0-9])" ||
  # 4.2.6.x < 4.2.6.3
  version =~ "^4\.2\.6\.[0-2]($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.2.6-secfix (4.2.6.3)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);
