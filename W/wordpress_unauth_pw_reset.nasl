#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100028);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-8295");
  script_bugtraq_id(98295);
  script_xref(name:"EDB-ID", value:"41963");

  script_name(english:"WordPress 2.3.0 - 4.8.3 Unauthorized Password Reset");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is 4.7.x. It is,
therefore, affected by a flaw in the wp_mail() function within file
wp-includes/pluggable.php due to the improper usage of the SERVER_NAME
variable, specifically when input from the HTTP Host header is
assigned to SERVER_NAME. An unauthenticated, remote attacker can
exploit this issue to reset arbitrary passwords by means of a crafted
'wp-login.php?action=lostpassword' request, which is then bounced or
resent, resulting in the transmission of the reset key to a mailbox on
an SMTP server under the attacker's control.

Note that exploitation of this vulnerability is not achievable in all
cases because it requires at least one of the following conditions :

  - The attacker can prevent the victim from receiving any
    e-mail messages for an extended period of time (such as
    five days).

  - The victim's e-mail system sends an auto-response
    containing the original message.

  - The victim manually composes a reply containing the
    original message.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a4aa4f1");
  # https://blog.dewhurstsecurity.com/2017/05/04/exploitbox-wordpress-security-advisories.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c466b63");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/ticket/25239");
  # https://httpd.apache.org/docs/2.4/mod/core.html#usecanonicalname
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f6ca2dd");
  script_set_attribute(attribute:"solution", value:
"There is no official fixed release available from the vendor at this
time.

It is possible to mitigate this vulnerability by taking steps to
ensure that SERVER_NAME is constructed from a static value. For
example, on Apache systems, enable the UseCanonicalName setting within
the Apache configuration. This will force PHP to use the configured
ServerName directive value instead of relying on the HTTP Host request
header, which can be manipulated by an attacker.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:X/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8295");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [{ "min_version":"2.3.0", "max_version" : "4.8.3" }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
