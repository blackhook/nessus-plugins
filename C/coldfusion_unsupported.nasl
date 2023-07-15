#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72091);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_xref(name:"IAVA", value:"0001-A-0507");

  script_name(english:"Adobe ColdFusion Unsupported Version Detection");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a web application
platform.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe ColdFusion running
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://helpx.adobe.com/support/programs/adobe-support-policies-supported-product-versions.html#sort-a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e683ec7");
  # https://helpx.adobe.com/support/programs/eol-matrix.html#63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75eac050");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe ColdFusion that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_ports("installed_sw/ColdFusion");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

var app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);

var install = get_single_install(
  app_name : app,
  port     : port
);

var longterm_support_lists = make_array(
  "^[0-6]($|\.)", make_array(
        'support_type' , 'out_of_support',
        'support_dates', 'No support dates are available.',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      ),
  "^7($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2010-02-07 (end of regular support) / 2012-02-07 (end of Extended Support)',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      ),
  "^8($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2012-07-31 (end of regular support) / 2014-07-31 (end of Extended Support)',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      ),
  "^9($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2014-12-31 (end of regular support) / 2016-12-31 (end of Extended Support)',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      ),
  "^10($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2017-05-16 (end of regular support) / 2019-05-16 (end of Extended Support)',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      ),
  "^11($|\.)",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2019-04-30 (end of regular support) / 2021-04-30 (end of Extended Support)',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      ),
  "^2016",  make_array(
        'support_type' , 'out_of_support',
        'support_dates', '2021-02-17 (end of regular support) / 2022-02-17 (end of Extended Support)',
        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
      )
#  "^2018",  make_array(
#        'support_type' , 'extended_support',
#        'support_dates', '2023-07-13 (end of regular support) / 2024-07-13 (end of Extended Support)',
#        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
#      )
#  "^2021",  make_array(
#        'support_type' , NULL,
#        'support_dates', '2025-11-10 (end of regular support) / 2026-11-10 (end of Extended Support)',
#        'support_url'  , 'https://helpx.adobe.com/support/programs/eol-matrix.html#63'
#      )
);

var supported_versions = '2018 / 2021';

# Determine support status.
var version = install['version'];
var dir = install['path'];
var v;
var obsolete = '';
foreach v (keys(longterm_support_lists))
{
  if (version =~ v)
  {
    if (longterm_support_lists[v]['support_type'] == "extended_support")
      set_kb_item(
        name:"www/coldfusion/"+longterm_support_lists[v]['support_type']+"/"+dir+"/"+version+"/"+port,
        value:longterm_support_lists[v]['support_dates']
      );
    else
      obsolete = v;

    break;
  }
}

var info;

if (obsolete)
{
  register_unsupported_product(product_name:"Adobe ColdFusion",
                               version:version, cpe_base:"adobe:coldfusion");
  if (report_verbosity > 0)
  {
    var info =
      '\n  Install location    : ' + build_url(port:port, qs:dir)  +
      '\n  Installed version   : ' + version;

    if (longterm_support_lists[v]['support_dates'])
      info += '\n  Support dates       : ' + longterm_support_lists[v]['support_dates'];
    if (longterm_support_lists[v]['support_url'])
      info += '\n  Announcement        : ' + longterm_support_lists[v]['support_url'];
    info += '\n  Supported versions  : ' + supported_versions + '\n';

    security_hole(port:port, extra:info);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir), version);
