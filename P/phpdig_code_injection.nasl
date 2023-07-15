#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12008);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2004-0068");
  script_bugtraq_id(9424);

  script_name(english:"PhpDig config.php relative_script_path Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be executed on the remote server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running phpdig, an http search engine written in PHP.
There is a flaw in this product that could allow an attacker to execute
arbitrary PHP code on this by forcing this set of CGI to include a PHP
script hosted on a third-party host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-0068");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpdig.net:phpdig");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpdig.net:phpdig");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (! can_host_php(port:port) ) exit(0);


function check_dir(path)
{
 local_var u, r, res;
 u = strcat(path, "/includes/config.php?relative_script_path=http://example.com");
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ("http://example.com/libs/.php" >< res) 
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
check_dir(path:dir);
}
