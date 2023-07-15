#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109345);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");
  script_xref(name:"IAVA", value:"0001-A-0578");

  script_name(english:"Oracle WebLogic Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a WebLogic
server.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Oracle WebLogic running
on the remote host is no longer supported per:

- Error Correction Support Dates for Oracle WebLogic Server (Doc ID
950131.1)

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/knowledge/Middleware/950131_1.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/knowledge/Middleware/944866_1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle WebLogic that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("weblogic_detect.nasl", "oracle_weblogic_server_installed.nbin");

  exit(0);
}

include('install_func.inc');

var apps = make_list();
var app, port, weblogic_ports, report, install, version;

if (get_install_count(app_name:'Oracle WebLogic Server') > 0)
  apps = make_list(apps, 'Oracle WebLogic Server');
else if (get_install_count(app_name:'WebLogic') > 0)
  apps = make_list(apps, 'WebLogic');

if (get_install_count(app_name:'JDeveloper\'s Integrated WebLogic Server')  > 0)
  apps = make_list(apps, 'JDeveloper\'s Integrated WebLogic Server');

if (get_install_count(app_name:'Oracle Data Integrator Embedded Weblogic Server')  > 0)
  apps = make_list(apps, 'Oracle Data Integrator Embedded Weblogic Server');

if (empty(apps)) audit(AUDIT_NOT_INST, 'Oracle WebLogic Server');

# function used to compare dates and report

function compare_2_eol_dates(version, eol_dates)
{
  var report, regex;

  foreach regex (keys(eol_dates))
  {
    if (preg(pattern:regex,string:version))
    {
      register_unsupported_product(
      product_name : app,
      version      : version,
      cpe_base     : 'oracle:weblogic_server'
      );

      report +=
      '\n  Installed version   : ' + version +
      '\n  End of support date : ' + eol_dates[regex] +
      '\n  End of support URL  : Refer to the \'See Also\' link' +
      '\n  Latest version      : ' + supported_versions +
      '\n';
      break;
    }
  }
    if (!isnull(report))
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    else
    audit(AUDIT_SUPPORTED, 'WebLogic Server', version);
}

# based on Error Correction Support Dates in the report_eol_url (see:also tinyurl)
eol_dates = make_array(
  "^[0-6]($|[^0-9])",           "2001/03/01",
  "^7\.[0-9]($|[^0-9])",        "2011/03/01",
  "^8\.[0-9]($|[^0-9])",        "2011/09/01",
  "^9\.[0-9]($|[^0-9])",        "2013/11/01",
  "^10\.[0-2]($|[^0-9])",       "2015/03/01",
  "^10\.3\.0($|[^0-9])",        "2017/01/01",
  "^10\.3\.1($|[^0-9])",        "2010/11/01",
  "^10\.3\.2($|[^0-9])",        "2011/04/01",
  "^10\.3\.3($|[^0-9])",        "2012/01/01",
  "^10\.3\.4($|[^0-9])",        "2012/05/01",
  "^10\.3\.5($|[^0-9])",        "2013/08/01",
  "^10\.3\.6($|[^0-9])",        "2021/12/01",
  "^12\.[0-1]\.[01]($|[^0-9])", "2018/01/01",
  "^12\.1\.2($|[^0-9])",        "2018/01/01",
  "^12\.2\.1\.0($|[^0-9])",     "2017/06/01",
  "^12\.2\.1\.1($|[^0-9])",     "2017/10/01",
  "^12\.2\.1\.2($|[^0-9])",     "2018/08/01"
# "^12\.2\.1\.3($|[^0-9])",     "2022/12/01"
);

var supported_versions = '12.1.3.0 / 12.2.1.3 / 12.2.1.4 / 14.1.1.0';
var supported = TRUE;

foreach app (apps)
{
  if (!empty_or_null(app))
  {
    # Checking for apps assoicated with our remote detection

    if (preg(pattern:'^WebLogic$', string:app))
    {
      weblogic_ports = get_kb_list("www/weblogic/ports");
      weblogic_ports = list_uniq(weblogic_ports);
      if (!empty_or_null(weblogic_ports))
      {
        foreach port (weblogic_ports)
        {
          version = get_kb_item('www/weblogic/' + port + '/version');
          if (!empty_or_null(version)) compare_2_eol_dates(version:version, eol_dates:eol_dates);
        }
      }
    }
    else
    {
      # Checking for apps assoicated with our local detection
      port = '';
      install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
      version = install['version'];
      if (version == UNKNOWN_VER) continue;
      compare_2_eol_dates(version:version, eol_dates:eol_dates);
    }
  }
}
