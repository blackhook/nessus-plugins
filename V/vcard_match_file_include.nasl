#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20133);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-3332");
  script_bugtraq_id(15207);

  script_name(english:"vCard define.inc.php match Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running vCard, a web-based electronic
postcard application from Belchior Foundry and written in PHP. 

The version of vCard installed on the remote host fails to sanitize
the 'match' parameter before using it in the 'admin/define.inc.php'
script to read other files.  By leveraging this flaw, an
unauthenticated attacker may be able to execute script files from
third-party hosts.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2005/Oct/353");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the vCard's 'admin' directory using, say, a
.htaccess file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-3332");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/vcard", "/vcards", "/ecard", "/cards", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read from a nonexistent host.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/admin/define.inc.php?",
      "match=http://example.com/" ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a PHP error.
  if (
    "Call to a member function on a non-object" >< res &&
    "/admin/define.inc.php" >< res
  ) {
    if (report_verbosity > 0) {
      report = string(
        "\n",
        res
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
