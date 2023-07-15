#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81551);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-9225");
  script_bugtraq_id(72094);

  script_name(english:"Symantec Data Center Security Server 'environment.jsp' Information Disclosure (SYM15-001)");
  script_summary(english:"Looks for 'environment.jsp'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Symantec Data Center Security Server running on the remote
host is affected by an information disclosure vulnerability in the
'/webui/admin/environment.jsp' script, which discloses sensitive
information about the server and software configuration.");
  # https://support.symantec.com/en_US/article.SYMSA1311.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0364a137");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Data Center Security version 6.0 MP1, and apply
the protection policy modifications described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9225");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_dcs_web_interface_detect.nbin", "http_version.nasl");
  script_require_keys("installed_sw/Symantec Data Center Security Server");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = 'Symantec Data Center Security Server';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8081);

install = get_single_install(app_name:appname, port:port);

res = http_send_recv3(method       : "GET",
                      port         : port,
                      item         : "/webui/admin/environment.jsp",
                      exit_on_fail : TRUE);

if("<title>Environment Information</title>" >< res[2] &&
   "\Symantec\" >< res[2] &&
   "<b>Your current working directory</b>" >< res[2])
{
  if(report_verbosity > 0)
  {
    report = '\nNessus was able to view sensitive information by visiting the following URL :\n' +
             '\n  ' + build_url(port:port, qs:'/webui/admin/environment.jsp') + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/webui/apps/sdcss'));
