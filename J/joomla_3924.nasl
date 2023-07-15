#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144980);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2021-23123", "CVE-2021-23124", "CVE-2021-23125");
  script_xref(name:"IAVA", value:"2021-A-0012-S");

  script_name(english:"Joomla 3.0.x < 3.9.24 Multiple Vulnerabilities (5830-joomla-3-9-24)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 3.0.x prior to
3.9.24. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in Joomla! 3.0.0 through 3.9.23. The lack of ACL checks in the orderPosition
    endpoint of com_modules leak names of unpublished and/or inaccessible modules. (CVE-2021-23123)

  - An issue was discovered in Joomla! 3.9.0 through 3.9.23. The lack of escaping in mod_breadcrumbs aria-
    label attribute allows XSS attacks. (CVE-2021-23124)

  - An issue was discovered in Joomla! 3.1.0 through 3.9.23. The lack of escaping of image-related parameters
    in multiple com_tags views cause lead to XSS attack vectors. (CVE-2021-23125)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5830-joomla-3-9-24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a9c5bd");
  # https://developer.joomla.org/security-centre/836-20210101-core-com-modules-exposes-module-names.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90d8b462");
  # https://developer.joomla.org/security-centre/837-20210102-core-xss-in-mod-breadcrumbs-aria-label-attribute.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c64320c8");
  # https://developer.joomla.org/security-centre/838-20210103-core-xss-in-com-tags-image-parameters.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bba042fb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23123");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-23125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'Joomla!', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '3.9.24' }
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
