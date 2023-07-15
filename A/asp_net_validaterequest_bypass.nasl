#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58601);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-3842", "CVE-2008-3843");

  script_name(english:"Microsoft ASP.NET ValidateRequest Filters Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The web application framework used on the remote host may be
susceptible to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"According to the HTTP headers received from the remote host, the web
server is configured to use the ASP.NET framework.

This framework includes the ValidateRequest feature, which is used by
ASP.NET web applications to filter user input in an attempt to prevent
cross-site scripting attacks.  However, this set of filters can be
bypassed if it is the sole mechanism used for protection by a web
application.");
  # https://web.archive.org/web/20121104165056/http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr08-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e41a641e");
  script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/en-us/library/bb355989.aspx");
  # https://msdn.microsoft.com/en-us/library/ms972969.aspx#securitybarriers_topic6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?553a368a");
  script_set_attribute(attribute:"solution", value:
"Determine if any ASP.NET web applications solely rely on the
ValidateRequest feature, and use additional protections if necessary.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3842");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

if (!get_kb_item("Settings/PCI_DSS"))
  audit(AUDIT_PCI);

port = get_http_port(default:80, asp:TRUE);
banner = get_http_banner(port:port);

# check the banner first
if (!isnull(banner))
{
  headers = parse_http_headers(status_line:banner, headers:banner);
  poweredby = headers['x-powered-by'];
  aspnet_version = headers['x-aspnet-version'];

  if (aspnet_version =~ '^1\\.' || aspnet_version =~ '^2\\.0')
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe following HTTP response header was received after requesting the' +
        '\nfollowing URL :\n' +
        '\nURL : ' + build_url(port:port, qs:'/') +
        '\nX-AspNet-Version : ' + aspnet_version + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  # the x-powered-by header doesn't indicate version, so only check it when
  # the x-aspnet-version header isn't present
  else if (!aspnet_version && 'ASP.NET' >< poweredby)
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe following HTTP response header was received after requesting the' +
        '\nfollowing URL :\n' +
        '\nURL : ' + build_url(port:port, qs:'/') +
        '\nX-Powered-By : ' + poweredby + '\n' +
        '\nIt is not possible to determine the version from the header, so this' +
        '\nfinding may be a false positive.\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}

# then check each dir (the x-aspnet-version header appears to show up on a per-app basis)
foreach dir (cgi_dirs())
{
  url = dir + '/';
  if (url == '/') continue;  # already checked this

  res = http_send_recv3(method:'HEAD', item:url, port:port, exit_on_fail:TRUE);
  headers = parse_http_headers(status_line:res[0], headers:res[1]);
  aspnet_version = headers['x-aspnet-version'];
  
  if (aspnet_version =~ '^1\\.' || aspnet_version =~ '^2\\.0')
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe following HTTP response header was received after requesting the' +
        '\nfollowing URL :\n' +
        '\nURL : ' + build_url(port:port, qs:url) +
        '\nX-AspNet-Version : ' + aspnet_version + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}

audit(AUDIT_HOST_NOT, 'affected');
