#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106631);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-6376",
    "CVE-2018-6377",
    "CVE-2018-6379",
    "CVE-2018-6380"
  );
  script_bugtraq_id(
    102916,
    102917,
    102918,
    102921
  );

  script_name(english:"Joomla! 1.5.0 < 3.8.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Joomla!
installation running on the remote web server is 1.5.0 or later but
prior to 3.8.4. It is, therefore, affected by multiple XSS and SQLi
vulnerabilities :

  - The XSS vulnerability in module chromes as noted in the
    20180101 announcement affects 3.0.0 through 3.8.3.
    (CVE-2018-6380)

  - The XSS vulnerability in com_fields as noted in the
    20180102 announcement affects 3.7.0 through 3.8.3.
    (CVE-2018-6377)

  - The XSS vulnerability in Uri class as noted in the
    20180103 announcement affects 1.5.0 through 3.8.3.
    (CVE-2018-6379)

  - The SQLi vulnerability in Hathor postinstall message
    as noted in the 20180103 announcement affects 1.5.0
    through 3.8.3. (CVE-2018-6379)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://developer.joomla.org/security-centre/718-20180101-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b2a148f");
  # https://developer.joomla.org/security-centre/720-20180102-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d012364d");
  # https://developer.joomla.org/security-centre/721-20180103-core-xss-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db1927db");
  # https://developer.joomla.org/security-centre/722-20180104-core-sqli-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e33b8acb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:80, php:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Joomla!", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "1.5.0", "fixed_version" : "3.8.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE, sqli:TRUE});
