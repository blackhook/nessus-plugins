#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159348);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2022-23793",
    "CVE-2022-23794",
    "CVE-2022-23796",
    "CVE-2022-23797",
    "CVE-2022-23798",
    "CVE-2022-23799",
    "CVE-2022-23800",
    "CVE-2022-23801"
  );
  script_xref(name:"IAVA", value:"2022-A-0130-S");
  script_xref(name:"IAVA", value:"2022-A-0490-S");

  script_name(english:"Joomla 2.5.x < 3.10.7 / 4.0.x < 4.1.1 Multiple Vulnerabilities (5857-joomla-4-1-1-and-3-10-7-release)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 2.5.x prior to
3.10.7 or 4.0.x prior to 4.1.1. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0. Extracting an specifilcy
    crafted tar package could write files outside of the intended path. (CVE-2022-23793)

  - An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0. Uploading a file name of an
    excess length causes the error. This error brings up the screen with the path of the source code of the
    web application. (CVE-2022-23794)

  - An issue was discovered in Joomla! 2.5.0 through 3.10.6 & 4.0.0 through 4.1.0. A user row was not bound to
    a specific authentication mechanism which could under very special circumstances allow an account
    takeover. (CVE-2022-23795)

  - An issue was discovered in Joomla! 3.7.0 through 3.10.6. Lack of input validation could allow an XSS
    attack using com_fields. (CVE-2022-23796)

  - An issue was discovered in Joomla! 3.0.0 through 3.10.6 & 4.0.0 through 4.1.0. Inadequate filtering on the
    selected Ids on an request could resulted into an possible SQL injection. (CVE-2022-23797)

  - An issue was discovered in Joomla! 2.5.0 through 3.10.6 & 4.0.0 through 4.1.0. Inadequate validation of
    URLs could result into an invalid check whether an redirect URL is internal or not. (CVE-2022-23798)

  - An issue was discovered in Joomla! 4.0.0 through 4.1.0. Under specific circumstances, JInput pollutes
    method-specific input bags with $_REQUEST data. (CVE-2022-23799)

  - An issue was discovered in Joomla! 4.0.0 through 4.1.0. Inadequate content filtering leads to XSS
    vulnerabilities in various components. (CVE-2022-23800)

  - An issue was discovered in Joomla! 4.0.0 through 4.1.0. Possible XSS atack vector through SVG embedding in
    com_media. (CVE-2022-23801)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5857-joomla-4-1-1-and-3-10-7-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?815408c9");
  # https://developer.joomla.org/security-centre/870-20220301-core-zip-slip-within-the-tar-extractor.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8fd972e");
  # https://developer.joomla.org/security-centre/871-20220302-core-path-disclosure-within-filesystem-error-messages.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f07a03d2");
  # https://developer.joomla.org/security-centre/872-20220303-core-user-row-are-not-bound-to-a-authentication-mechanism.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9ff201d");
  # https://developer.joomla.org/security-centre/873-20220304-core-missing-input-validation-within-com-fields-class-inputs.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09b620b1");
  # https://developer.joomla.org/security-centre/874-20220305-core-inadequate-filtering-on-the-selected-ids.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d38c9b23");
  # https://developer.joomla.org/security-centre/875-20220306-core-inadequate-validation-of-internal-urls.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64d3bf00");
  # https://developer.joomla.org/security-centre/876-20220307-core-variable-tampering-on-jinput-request-data.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26f99ee3");
  # https://developer.joomla.org/security-centre/877-20220308-core-inadequate-content-filtering-within-the-filter-code.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?709bfd66");
  # https://developer.joomla.org/security-centre/878-20220309-core-xss-attack-vector-through-svg.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?240c3d8d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.10.7 / 4.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23797");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23799");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '2.5.0', 'max_version' : '3.10.6', 'fixed_version' : '3.10.7' },
  { 'min_version' : '4.0.0', 'max_version' : '4.1.0', 'fixed_version' : '4.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE, 'xss':TRUE}
);
