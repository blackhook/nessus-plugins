#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138598);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_name(english:"Magento Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a web application.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Magento on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://experienceleague.adobe.com/docs/commerce-operations/release/lifecycle-policy.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94afbdb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Magento that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Unsupported Software");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magentocommerce:magento");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magento:magento");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("magento_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");
include("install_func.inc");


app = "Magento";
get_install_count(app_name:app, exit_if_zero:TRUE);


port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install["version"];
type    = install["License Type"];

# per https://magento.com/sites/default/files/magento-software-lifecycle-policy.pdf
ent_eol_dates = make_array(
  "^1\.9($|[^0-9])",      "2012/07/31",
  "^1\.10($|[^0-9])",     "2013/02/28",
  "^1\.11($|[^0-9])",     "2013/08/31",
  "^1\.12($|[^0-9])",     "2014/04/30",
  "^1\.13($|[^0-9])",     "2020/06/30",
  "^1\.14($|[^0-9])",     "2020/06/30",
  "^2\.0($|[^0-9])",      "2018/03/31",
  "^2\.1($|[^0-9])",      "2019/06/30",
  "^2\.2($|[^0-9])",      "2019/12/31",
  "^2\.3($|[^0-9])",      "2022/09/08"
# "^2\.4\.[0-3]",         "2022/11/28"  upcoming v2.4.0 - 2.4.3 EOS
);


# per https://magento.com/sites/default/files/magento-open-source-software-maintenance-policy.pdf
open_source_eol_dates = make_array(
  "^1\.0($|[^0-9])",     "2010/03/31",
  "^1\.1($|[^0-9])",     "2010/07/31",
  "^1\.2($|[^0-9])",     "2010/12/31",
  "^1\.3($|[^0-9])",     "2011/03/31",
  "^1\.4($|[^0-9])",     "2012/02/28",
  "^1\.5($|[^0-9])",     "2020/06/30",
  "^1\.6($|[^0-9])",     "2020/06/30",
  "^1\.7($|[^0-9])",     "2020/06/30",
  "^1\.8($|[^0-9])",     "2020/06/30",
  "^1\.9($|[^0-9])",     "2020/06/30",
  "^2\.0($|[^0-9])",     "2018/03/31",
  "^2\.1($|[^0-9])",     "2019/06/30",
  "^2\.2($|[^0-9])",     "2019/09/30",
  "^2\.3($|[^0-9])",     "2022/09/08"
# "^2\.4\.[0-3]",        "2022/11/28"  upcoming v2.4.0 - 2.4.3 EOS   
);

latest   = "2.4.x";
supported = TRUE;

if (type == ('Open Source') || ('Community'))
{
  foreach regex (keys(open_source_eol_dates))
  {
    if (version =~ regex)
    {
      supported = FALSE;
      report_eol_date = open_source_eol_dates[regex];
      report_eol_url = "https://magento.com/sites/default/files/magento-open-source-software-maintenance-policy.pdf";
      break;
    }
  }
}
else
  {
    foreach regex (keys(ent_eol_dates))
    {
      if (version =~ regex)
      {
        supported = FALSE;
        report_eol_date = ent_eol_dates[regex];
        report_eol_url = "https://magento.com/sites/default/files/magento-software-lifecycle-policy.pdf";
        break;
      }
    }
}

if (!supported)
{
  register_unsupported_product(
    product_name : app,
    cpe_base     : "magento:magento",
    version      : version
  );

  report =
    '\n  Installed version   : ' + version +
    '\n  End of support date : ' + report_eol_date +
    '\n  End of support URL  : ' + report_eol_url +
    '\n  Latest version      : ' + latest +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_SUPPORTED, app, version);
