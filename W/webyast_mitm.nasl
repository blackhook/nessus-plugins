#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64244);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-0435");
  script_bugtraq_id(57511);
  script_xref(name:"TRA", value:"TRA-2013-02");
  script_xref(name:"CERT", value:"806908");

  script_name(english:"WebYaST Host Modification MiTM");
  script_summary(english:"Checks if webyast hosts can be edited");

  script_set_attribute(attribute:"synopsis", value:
"The application hosted on the remote web server is vulnerable to a
man-in-the-middle attack.");
  script_set_attribute(attribute:"description", value:
"The WebYaST web client hosted on the remote web server is vulnerable to
a man-in-the-middle attack.  Authentication is not required to modify
which hosts the WebYaST web client is configured to connect to.  A
remote, unauthenticated attacker could exploit this by causing all
WebYaST traffic to be routed through a host under their control.  This
could result in the disclosure of sensitive information (e.g., usernames
and passwords) and could allow an attacker to modify requests in
transit.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-02");
  # https://lists.opensuse.org/opensuse-security-announce/2013-01/msg00008.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec098502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2012-0435/");
  # http://download.novell.com/patch/finder/?keywords=7c947289145036c838e04ef674b59d7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?284f17bb");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 7236.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:suse:webyast");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webyast_detect.nasl");
  script_require_keys("www/webyast_client");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 54984);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:54984);
install = get_install_from_kb(appname:'webyast_client', port:port, exit_on_fail:TRUE);

base_url = build_url(qs:install['dir'], port:port);
hosts_url = install['dir'] + '/hosts/1/edit';
res = http_send_recv3(method:'GET', item:hosts_url, port:port, exit_on_fail:TRUE);

# in the non-vulnerable version, the page that allows you to edit
# hosts does not exist
if ('<h1>Editing YaST-Web-Service</h1>' >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'WebYaST Web Client', base_url);

if (report_verbosity > 0)
{
  report = get_vuln_report(items:hosts_url, port:port);
  security_warning(port:port, extra:report);
}
else security_warning(port);
