#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76496);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-0242");
  script_bugtraq_id(67534);

  script_name(english:"Apache mod_wsgi < 3.4 Remote Information Disclosure");
  script_summary(english:"Checks the version of mod_wsgi in the Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server module has a remote information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the web server banner, the version of mod_wsgi running on
the remote host is prior to version 3.4. It is, therefore, affected by
a remote information disclosure vulnerability.

The issue is due to the handling of corrupted 'Response Content-Type'
headers. A remote attacker could potentially access sensitive
information in memory chunks.");
  # https://modwsgi.readthedocs.io/en/latest/release-notes/version-3.4.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac3fd9fb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to mod_wsgi 3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modwsgi:mod_wsgi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);
if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");

regex = "mod_wsgi/([0-9rc.]+)";
matches = pregmatch(pattern:regex, string:install["modules"]);
if (isnull(matches)) exit(0, "The server banner from the web server listening on port "+port+" doesn't include the mod_wsgi version.");
else version = matches[1];

suffixes = make_array(
  -2, "rc(\d+)",
  -1, "c(\d+)"
);

fixed = '3.4';
if (ver_compare(ver:version, fix:fixed, regexes:suffixes) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server_header +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "mod_wsgi", port, version);
