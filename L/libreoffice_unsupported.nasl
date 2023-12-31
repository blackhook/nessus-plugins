#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80831);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0545");

  script_name(english:"LibreOffice Unsupported Version Detection");
  script_summary(english:"Checks for LibreOffice on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is no longer
supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
LibreOffice on the remote Windows host is no longer supported.
LibreOffice is an office document creation and editing suite.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.documentfoundation.org/ReleasePlan");
  # L3 support
  script_set_attribute(attribute:"see_also", value:"https://www.documentfoundation.org/gethelp/developers/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of LibreOffice that is currently supported.
Alternatively, contact a LibreOffice Certified Developer to obtain L3
support.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2020 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Leave commented versions until their EOL dates
eol_dates = make_array(
  #"^5\.3($|[^0-9])"    , "2017/11/26",
  #"^5\.2($|[^0-9])"    , "2017/06/04",
  "^5\.1($|[^0-9])"    , "2016/11/27",
  "^5\.0($|[^0-9])"    , "2016/05/29",
  "^4\.4($|[^0-9])"    , "2015/12/31",
  "^4\.3($|[^0-9])"    , "2015/05/27",
  "^4\.2($|[^0-9])"    , "2015/01/06",
  "^4\.1($|[^0-9])"    , "2014/05/28",
  "^4\.0($|[^0-9])"    , "2013/11/21",
  "^3\.6($|[^0-9])"    , "2013/08/15",
  "^3\.5($|[^0-9])"    , "2012/11/08",
  "^3\.4($|[^0-9])"    , "2012/04/19",
  "^3\.3($|[^0-9])"    , "2011/09/17"
);
eol_urls  = make_array(
  "^5\.3($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/5.3#End_of_Life",
  "^5\.2($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/5.2#End_of_Life",
  "^5\.1($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/5.1#End_of_Life",
  "^5\.0($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/5.0#End_of_Life",
  "^4\.4($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/4.4#End_of_Life",
  "^4\.3($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/4.3#End_of_Life",
  "^4\.2($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/4.2#End_of_Life",
  "^4\.1($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/4.1#End_of_Life",
  "^4\.0($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/4.0#End_of_Life",
  "^3\.6($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/3.6#End_of_Life",
  "^3\.5($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/3.5#End_of_Life",
  "^3\.4($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/3.4#End_of_Life",
  "^3\.3($|[^0-9])", "https://wiki.documentfoundation.org/ReleasePlan/3.3#End_of_Life"
);

app_name = "LibreOffice";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version    = install['version'];
version_ui = install['display_version'];
path       = install['path'];

# Versions below 3.3 do *not* exist and should not
# be found. However, if we do, an error needs to
# be generated.
if (version =~ "^([0-2]|3\.[0-2])($|[^0-9])")
  exit(1, "The detected version, "+version_ui+", is not a legitimate LibreOffice version.");

default_eol_url = "https://wiki.documentfoundation.org/ReleasePlan";
unsupported = FALSE;

foreach ver_regex (keys(eol_dates))
{
  if (version !~ ver_regex) continue;

  eol_date = eol_dates[ver_regex];

  if (!isnull(eol_urls[ver_regex]))
    eol_url = eol_urls[ver_regex];
  else
    eol_url = default_eol_url;

  unsupported = TRUE;
  break;
}

if (unsupported)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  register_unsupported_product(
    product_name : "LibreOffice",
    cpe_base     : "libreoffice:libreoffice",
    version      : version_ui
  );

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui  +
      '\n  EOL date          : ' + eol_date  +
      '\n  EOL URL           : ' + eol_url  +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
