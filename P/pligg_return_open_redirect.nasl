#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43027);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-4788");
  script_bugtraq_id(37185);
  script_xref(name:"SECUNIA", value:"37349");

  script_name(english:"Pligg login.php return Parameter Arbitrary Site Redirect");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that has an open redirect.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Pligg, an open source content management
system. 

The installed version of Pligg contains an open redirect, in the
'return' parameter of its 'login.php' script.  This could be abused to
launch a phishing attack to trick users into visiting malicious
sites.

Note that this install is also likely to be affected by several other
vulnerabilities, including cross-site request forgery and cross-site
scripting vulnerabilities, although Nessus has not checked for them.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pligg version 1.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-4788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pligg:pligg_cms");
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


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


redirect = "http://www.example.com/";


# Loop through various directories.
if (thorough_tests) dirs = list_uniq("/pligg", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  url = string(
    dir, "/login.php?",
    "return=", redirect
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  # There's a problem if our redirect appears in the login form.
  if (
    '<input type="hidden" name="return" value="'+redirect+'"/>' >< res[2] &&
    (
      'meta name="description" content="Pligg is an' >< res[2] ||
      'Pligg <a href="http://www.pligg.com/">Content Management System</a>' >< res[2]
    )
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
exit(0, "No vulnerable Pligg installs were found on port "+port);
