#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86900);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213");

  script_name(english:"LibreOffice < 4.4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is
prior to 4.4.5. It is, therefore, affected by the following
vulnerabilities :

  - An information disclosure vulnerability exists due to
    the use of stored LinkUpdateMode configuration
    information in OpenDocument Format files and templates
    when handling links. A remote attacker can exploit this,
    via a specially crafted ODF document, to to obtain
    sensitive information. (CVE-2015-4551)

  - An integer underflow condition exists in the
    ReadJobSetup() function due to improper validation of
    user-supplied input when handling printer settings. A
    remote attacker can exploit this, via specially crafted
    PrinterSetup data in an ODF document, to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2015-5212)

  - An integer underflow condition exists in the
    WW8ScannerBase::OpenPieceTable() function due to
    improper validation of user-supplied input when handling
    the PieceTable counter. A remote attacker can exploit
    this, via a specially crafted .DOC file, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2015-5213)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2015-4551/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdf2c164");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2015-5212/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a5c0096");
  # https://www.libreoffice.org/about-us/security/advisories/cve-2015-5213/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b2d335c");
  script_set_attribute(attribute:"see_also", value:"http://listarchives.documentfoundation.org/www/announce/msg00241.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 4.4.5 (4.4.5.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "LibreOffice";

get_kb_item_or_exit("SMB/Registry/Enumerated");

install    = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
version_ui = install['display_version'];
path       = install['path'];

if (
  # < 4.x
  version =~ "^[0-3]($|[^0-9])" ||
  # 4.x < 4.4.5
  version =~ "^(4\.[0-3]|4\.4\.[0-4])($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.4.5 (4.4.5.2)' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version_ui, path);
