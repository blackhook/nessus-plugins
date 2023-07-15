#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97635);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2017-6514",
    "CVE-2017-6814",
    "CVE-2017-6815",
    "CVE-2017-6816",
    "CVE-2017-6817",
    "CVE-2017-6818",
    "CVE-2017-6819"
  );
  script_bugtraq_id(
    96598,
    96600,
    96601,
    96602,
    108459
  );

  script_name(english:"WordPress < 4.7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.7.3.
It is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in the
    wp_playlist_shortcode() function within the
    /wp-includes/media.php script due to a failure to
    validate input passed via audio file metadata before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session.

  - A cross-site redirection vulnerability exists due to
    a failure to validate input passed via control
    characters before returning it to users. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted link, to redirect a user from an
    intended legitimate website to an arbitrary website of
    the attacker's choosing.

  - An unspecified flaw exists in the plugin deletion
    functionality that allows an authenticated, remote
    attacker to delete unintended files.

  - A cross-site scripting (XSS) vulnerability exists due to
    a failure to validate input to video URLs in YouTube
    embeds before returning it to users. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session.

  - A cross-site scripting (XSS) vulnerability exists due to
    a failure to validate input to taxonomy term names
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session.

  - A cross-site request forgery (XSRF) vulnerability exists
    in the Press This functionality, specifically within
    /wp-admin/press-this.php when handling HTTP requests,
    due to a failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit this, by convincing a user to follow a
    specially crafted link, to cause excessive consumption
    of server resources.

  - A DOM-based cross-site scripting (XSS) vulnerability
    exists in the renderTracks() function within the
    /wp-includes/js/mediaelement/wp-playlist.min.js script
    due to a failure to validate input passed via audio file
    metadata before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session.
  
  - A directory traversal vulnerability exists in WordPress' wp-json component due to an error in post listing. An 
    unauthenticated, remote attacker can exploit this, by sending a URI that contains directory traversal characters, 
    to disclose the contents of files located outside of the server's restricted path.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?071b0e36");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.7.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6815");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");

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

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'WordPress', port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version':'2.8.1', 'fixed_version':'3.7.19', 'fixed_display' : '3.7.19 / 4.7.3' },
  { 'min_version':'3.8', 'fixed_version':'3.8.19', 'fixed_display' : '3.8.19 / 4.7.3' },
  { 'min_version':'3.9', 'fixed_version':'3.9.17', 'fixed_display' : '3.9.17 / 4.7.3' },
  { 'min_version':'4.0', 'fixed_version':'4.0.16', 'fixed_display' : '4.0.16 / 4.7.3' },
  { 'min_version':'4.1', 'fixed_version':'4.1.16', 'fixed_display' : '4.1.16 / 4.7.3' },
  { 'min_version':'4.2', 'fixed_version':'4.2.13', 'fixed_display' : '4.2.13 / 4.7.3' },
  { 'min_version':'4.3', 'fixed_version':'4.3.9', 'fixed_display' : '4.3.9 / 4.7.3' },
  { 'min_version':'4.4', 'fixed_version':'4.4.8', 'fixed_display' : '4.4.8 / 4.7.3' },
  { 'min_version':'4.5', 'fixed_version':'4.5.7', 'fixed_display' : '4.5.7 / 4.7.3' },
  { 'min_version':'4.6', 'fixed_version':'4.6.4', 'fixed_display' : '4.6.4 / 4.7.3' },
  { 'min_version':'4.7', 'fixed_version':'4.7.3', 'fixed_display' : '4.7.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE, xsrf:TRUE}
);
