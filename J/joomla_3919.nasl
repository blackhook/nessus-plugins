#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137366);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2020-13760",
    "CVE-2020-13761",
    "CVE-2020-13762",
    "CVE-2020-13763"
  );
  script_xref(name:"IAVA", value:"2020-A-0244-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Joomla 2.5.x < 3.9.19 Multiple Vulnerabilities (5812-joomla-3-9-19)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 2.5.x prior to
3.9.19. It is, therefore, affected by multiple vulnerabilities.

  - In Joomla! before 3.9.19, lack of input validation in
    the heading tag option of the Articles - Newsflash and
    Articles - Categories modules allows XSS.
    (CVE-2020-13761)

  - In Joomla! before 3.9.19, the default settings of the
    global textfilter configuration do not block HTML inputs
    for Guest users. (CVE-2020-13763)

  - In Joomla! before 3.9.19, incorrect input validation of
    the module tag option in com_modules allows XSS.
    (CVE-2020-13762)

  - In jQuery versions greater than or equal to 1.2 and
    before 3.5.0, passing HTML from untrusted sources - even
    after sanitizing it - to one of jQuery's DOM
    manipulation methods (i.e. .html(), .append(), and
    others) may execute untrusted code. This problem is
    patched in jQuery 3.5.0. (CVE-2020-11022)

  - In jQuery versions greater than or equal to 1.0.3 and
    before 3.5.0, passing HTML containing  elements
    from untrusted sources - even after sanitizing it - to
    one of jQuery's DOM manipulation methods (i.e. .html(),
    .append(), and others) may execute untrusted code. This
    problem is patched in jQuery 3.5.0. (CVE-2020-11023)

  - In Joomla! before 3.9.19, missing token checks in
    com_postinstall lead to CSRF. (CVE-2020-13760)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5812-joomla-3-9-19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66a75060");
  # https://developer.joomla.org/security-centre/813-20200601-core-xss-in-modules-heading-tag-option.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eddec97");
  # https://developer.joomla.org/security-centre/814-20200602-core-inconsistent-default-textfilter-settings.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3f2593d");
  # https://developer.joomla.org/security-centre/815-20200603-core-xss-in-com-modules-tag-options.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0796329");
  # https://developer.joomla.org/security-centre/816-20200604-core-xss-in-jquery-htmlprefilter.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?560bc965");
  # https://developer.joomla.org/security-centre/817-20200605-core-csrf-in-com-postinstall.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?478821e3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13760");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

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
  { 'min_version' : '2.5.0', 'max_version' : '3.9.18', 'fixed_version' : '3.9.19' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'xsrf':TRUE}
);
