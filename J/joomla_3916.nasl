#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134403);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2020-10238",
    "CVE-2020-10239",
    "CVE-2020-10240",
    "CVE-2020-10241",
    "CVE-2020-10242",
    "CVE-2020-10243"
  );
  script_xref(name:"IAVA", value:"2020-A-0102-S");

  script_name(english:"Joomla 1.7.x < 3.9.16 Multiple Vulnerabilities (5783-joomla-3-9-16)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 1.7.x prior to
3.9.16. It is, therefore, affected by multiple vulnerabilities.

  - Missing token checks in the image actions of
    com_templates causes CSRF vulnerabilities.
    (CVE-2020-10241)

  - Inadequate handling of CSS selectors in the Protostar
    and Beez3 JavaScript allow XSS attacks. (CVE-2020-10242)

  - Various actions in com_templates lack the required ACL
    checks, leading to various potential attack vectors.
    (CVE-2020-10238)

  - Missing length checks in the user table can lead to the
    creation of users with duplicate usernames and/or email
    addresses. (CVE-2020-10240)

  - Incorrect Access Control in the SQL fieldtype of
    com_fields allows access for non-superadmin users.
    (CVE-2020-10239)

  - The lack of type casting of a variable in SQL statement
    leads to a SQL injection vulnerability in the Featured
    Articles frontend menutype. (CVE-2020-10243)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5783-joomla-3-9-16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c4b1ab9");
  # https://developer.joomla.org/security-centre/802-20200301-core-csrf-in-com-templates-image-actions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fad2b0db");
  # https://developer.joomla.org/security-centre/803-20200302-core-xss-in-protostar-and-beez3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec44c9a2");
  # https://developer.joomla.org/security-centre/804-20200303-core-incorrect-access-control-in-com-templates.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf0a41ab");
  # https://developer.joomla.org/security-centre/805-20200304-core-identifier-collisions-in-com-users.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6884bdb7");
  # https://developer.joomla.org/security-centre/806-20200305-core-incorrect-access-control-in-com-fields-sql-field.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e255799");
  # https://developer.joomla.org/security-centre/807-20200306-core-sql-injection-in-featured-articles-menu-parameters.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18f6bfa0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10243");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '1.7.0', 'max_version' : '3.9.15', 'fixed_version' : '3.9.16' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE, xsrf:TRUE, sqli:TRUE}
);
