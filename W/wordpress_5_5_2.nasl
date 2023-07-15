##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142420);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2020-28032",
    "CVE-2020-28033",
    "CVE-2020-28034",
    "CVE-2020-28035",
    "CVE-2020-28036",
    "CVE-2020-28037",
    "CVE-2020-28038",
    "CVE-2020-28040"
  );
  script_xref(name:"IAVA", value:"2020-A-0507-S");

  script_name(english:"WordPress < 5.5.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of WordPress installed on the remote host is affected
by multiple vulnerabilities: 

  - A deserialization vulnerability exists in wp-includes/Requests/Utility/FilteredIterator.php. An 
  unauthenticated, remote attacker can exploit this, by sending specially crafted serialized payloads
  to an affected instance, to execute arbitrary code on the target host (CVE-2020-28032).

  - Multiple privilege escalation vulnerabilities exist in the XML-RPC component of Wordpress. An 
  unauthenticated, remote attacker can exploit these, to gain privileged access to an affected 
  host (CVE-2020-28035, CVE-2020-28036).

  - A remote code execution vulnerability exists in the is_blog_installed function of 
  wp-includes/functions.php. An unauthenticated, remote attacker can exploit this to bypass authentication 
  and execute arbitrary commands (CVE-2020-28037).   
 
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  # https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd17652d");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/wordpress-version/version-5-5-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 5.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

app = 'WordPress';
get_install_count(app_name:app, exit_if_zero:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '3.7', 'fixed_version' : '3.7.35'},
  { 'min_version' : '3.8', 'fixed_version' : '3.8.35'},
  { 'min_version' : '3.9', 'fixed_version' : '3.9.33'},
  { 'min_version' : '4.0', 'fixed_version' : '4.0.32'},
  { 'min_version' : '4.1', 'fixed_version' : '4.1.32'},
  { 'min_version' : '4.2', 'fixed_version' : '4.2.29'},
  { 'min_version' : '4.3', 'fixed_version' : '4.3.25'},
  { 'min_version' : '4.4', 'fixed_version' : '4.4.24'},
  { 'min_version' : '4.5', 'fixed_version' : '4.5.23'},
  { 'min_version' : '4.6', 'fixed_version' : '4.6.20'},
  { 'min_version' : '4.7', 'fixed_version' : '4.7.19'},
  { 'min_version' : '4.8', 'fixed_version' : '4.8.15'},
  { 'min_version' : '4.9', 'fixed_version' : '4.9.16'},
  { 'min_version' : '5.0', 'fixed_version' : '5.0.11'},
  { 'min_version' : '5.1', 'fixed_version' : '5.1.7'},
  { 'min_version' : '5.2', 'fixed_version' : '5.2.8'},
  { 'min_version' : '5.3', 'fixed_version' : '5.3.5'},
  { 'min_version' : '5.4', 'fixed_version' : '5.4.3'},
  { 'min_version' : '5.5', 'fixed_version' : '5.5.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags: {'xss':TRUE}
);
