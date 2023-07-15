#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109318);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"0001-A-0519");

  script_name(english:"Atlassian JIRA Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of Atlassian JIRA.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Atlassian JIRA running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that any new patches for previous versions are unofficial and are
not guaranteed to be continued in the future.");
  # https://confluence.atlassian.com/support/atlassian-support-end-of-life-policy-201851003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1ae64c0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Atlassian JIRA that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"The software is unsupported.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA");
  script_require_ports("Services/www", 80, 8080, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

eol_info = {
  # 3.x
  '3.0' : { 'Date' : '2006/11/03' },
  '3.1' : { 'Date' : '2007/03/09' },
  '3.2' : { 'Date' : '2007/09/15' },
  '3.3' : { 'Date' : '2007/10/20' },
  '3.4' : { 'Date' : '2008/01/06' },
  '3.5' : { 'Date' : '2008/03/22' },
  '3.6' : { 'Date' : '2008/09/18' },
  '3.7' : { 'Date' : '2009/02/21' },
  '3.8' : { 'Date' : '2009/04/16' },
  '3.9' : { 'Date' : '2009/07/08' },
  # 3.10 - 3.12:
  # https://web.archive.org/web/20100209033738/http://confluence.atlassian.com/display/Support/Atlassian+Support+End+of+Life+Policy
  # http://www.nessus.org/u?9aab4d87
  '3.10': { 'Date' : '2009/08/20',
            'URL'  : 'http://www.nessus.org/u?9aab4d87' },
  '3.11': { 'Date' : '2009/09/25',
            'URL'  : 'http://www.nessus.org/u?9aab4d87' },
  '3.12': { 'Date' : '2010/04/30',
            'URL'  : 'http://www.nessus.org/u?9aab4d87' },
  '3.13': { 'Date' : '2011/07/21',
            'URL'  : 'https://confluence.atlassian.com/jirakb/blog/2011/08/jira-3-13-end-of-life' },
  # 4.x
  '4.0' : { 'Date' : '2012/02/26',
            'URL'  : 'https://confluence.atlassian.com/jirakb/blog/2012/02/jira-4-0-x-support-end-of-life' },
  # 4.1:
  # https://web.archive.org/web/20120426140434/http://confluence.atlassian.com:80/display/Support/Atlassian+Support+End+of+Life+Policy
  # http://www.nessus.org/u?bd6e33b6
  '4.1' : { 'Date' : '2012/06/18',
            'URL'  : 'http://www.nessus.org/u?bd6e33b6' },
  '4.2' : { 'Date' : '2013/02/08',
            'URL'  : 'https://confluence.atlassian.com/jirakb/blog/2013/02/it-s-the-end-of-the-road-for-jira-4-2'},
  '4.3' : { 'Date' : '2013/05/27',
            'URL'  : 'https://confluence.atlassian.com/jirakb/blog/2013/05/it-s-the-end-of-the-road-for-jira-4-3'},
  '4.4' : { 'Date' : '2014/02/22',
            'URL'  : 'https://confluence.atlassian.com/jirakb/blog/2014/02/it-s-the-end-of-the-road-for-jira-4-4'},
  # 5.x
  '5.0' : { 'Date' : '2014/07/01',
            'URL'  : 'https://confluence.atlassian.com/jirakb/blog/2014/07/hasta-la-vista-jira-5-0' },
  # 5.1 - 5.2:
  # https://web.archive.org/web/20130623100038/http://confluence.atlassian.com/display/Support/Atlassian+Support+End+of+Life+Policy
  # http://www.nessus.org/u?419c60eb
  '5.1' : { 'Date' : '2014/10/31',
            'URL'  : 'http://www.nessus.org/u?419c60eb' },
  '5.2' : { 'Date' : '2015/04/19',
            'URL'  : 'http://www.nessus.org/u?419c60eb' },
  # 6.x
  # 6.0 - 6.4
  # https://web.archive.org/web/20150626203239/http://confluence.atlassian.com/display/Support/Atlassian+Support+End+of+Life+Policy
  # http://www.nessus.org/u?36f76b3e
  '6.0' : { 'Date' : '2015/09/03',
            'URL'  : 'http://www.nessus.org/u?36f76b3e' },
  '6.1' : { 'Date' : '2016/05/22',
            'URL'  : 'http://www.nessus.org/u?36f76b3e' },
  '6.2' : { 'Date' : '2016/06/11',
            'URL'  : 'http://www.nessus.org/u?36f76b3e' },
  '6.3' : { 'Date' : '2016/07/08',
            'URL'  : 'http://www.nessus.org/u?36f76b3e' },
  '6.4' : { 'Date' : '2017/03/17',
            'URL'  : 'http://www.nessus.org/u?36f76b3e' },
  # 7.x
  # 7.0 - 7.1
  # https://web.archive.org/web/20171101022150/https://confluence.atlassian.com/support/atlassian-support-end-of-life-policy-201851003.html
  '7.0' : { 'Date' : '2017/10/06',
            'URL'  : 'http://www.nessus.org/u?daa5dd0c' },
  '7.1' : { 'Date' : '2018/02/10',
            'URL'  : 'http://www.nessus.org/u?daa5dd0c' },
  '7.2' : { 'Date' : '2018/02/10',
            'URL'  : 'http://www.nessus.org/u?daa5dd0c' },
  '7.3' : { 'Date' : '2018/02/10',
            'URL'  : 'http://www.nessus.org/u?daa5dd0c' }

};

latest = "8.0.x";

port = get_http_port(default:8080);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

dir         = install["path"];
version     = install["version"];
install_loc = build_url(port:port, qs:dir);

report_eol = {};

# Determine branch (e.g. 4.1)
ver_split = split(version, sep:'.', keep:FALSE);
branch = ver_split[0] + '.' + ver_split[1];

# Check if branch is in mappings above
if (!empty_or_null(eol_info[branch]))
{
  if (!empty_or_null(eol_info[branch]['Date']))
  {
    report_eol['Date'] = eol_info[branch]['Date'];
  
    # URL is available
    if (!empty_or_null(eol_info[branch]['URL']))
      report_eol['URL'] = eol_info[branch]['URL'];
    # URL is not available -- note the two year policy in report
    else
    {
      # Determine last minor iteration release date by subtracting 2 years
      date_split = split(report_eol['Date'], sep:'/', keep:FALSE);
      if (max_index(date_split) == 3)
      {
        new_year     = int(date_split[0]) - 2;
        release_date = new_year + "/" + date_split[1] + "/" + date_split[2];

        report_eol['Note'] =
          'End of support date is based off the two year support policy. The last minor iteration was released ' + release_date;
      }
    }
  }
}
# Version is not in mappings but old
else if (version =~ "^[0-2]\.")
  report_eol['Note'] = 'End of support date not available but is presumed to no longer be supported.';
else
  audit(AUDIT_WEB_APP_SUPPORTED, app, install_loc, version);

register_unsupported_product(
  product_name : app,
  cpe_base     : "atlassian:jira",
  version      : version
);

report =
  '\n  URL                 : ' + install_loc +
  '\n  Installed version   : ' + version;

if (!empty_or_null(report_eol['Date']))
 report +=
  '\n  End of support date : ' + report_eol['Date'];

if (!empty_or_null(report_eol['URL']))
 report +=
  '\n  End of support URL  : ' + report_eol['URL'];

report +=
  '\n  Latest version      : ' + latest +
  '\n';

if (!empty_or_null(report_eol['Note']))
 report += '\n' + report_eol['Note'] + '\n';


security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
