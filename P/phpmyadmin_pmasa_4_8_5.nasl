#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126705);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-6798", "CVE-2019-6799");

  script_name(english:"phpMyAdmin 4.0 < 4.8.5 Multiple Vulnerabilities (PMASA-2019-1), (PMASA-2019-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.0.x prior to
4.8.5. It is, therefore, affected by multiple vulnerabilities.

  - When AllowArbitraryServer configuration set to true,
    with the use of a rogue MySQL server, an attacker can
    read any file on the server that the web server's user
    can access.phpMyadmin attempts to block the use of LOAD
    DATA INFILE, but due to a bug in PHP, this check is not
    honored. Additionally, when using the 'mysql' extension,
    mysql.allow_local_infile is enabled by default. Both of
    these conditions allow the attack to occur.
    (CVE-2019-6799)

  - A vulnerability was reported where a specially crafted
    username can be used to trigger an SQL injection attack
    through the designer feature. (CVE-2019-6798)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2019-1/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2019-2/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.8.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89, 661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'phpMyAdmin', port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '4.0', 'max_version' : '4.8.4', 'fixed_version' : '4.8.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
