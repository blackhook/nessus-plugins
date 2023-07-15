#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(143380);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"IAVA", value:"2020-A-0549-S");

  script_name(english:"Joomla 1.7.x < 3.9.23 Multiple Vulnerabilities (5828-joomla-3-9-23)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Joomla! running on the remote web server is 1.7.x prior to
3.9.23. It is, therefore, affected by multiple vulnerabilities.

  - The autosuggestion feature of com_finder did not respect the access level of the corresponding terms.

  - The global configuration page does not remove secrets from the HTML output, disclosing the current
    values.

  - The folder parameter of mod_random_image lacked input validation, leading to a path traversal
    vulnerability.

  - Improper filter blacklist configuration leads to a SQL injection vulnerability in the backend user list.

  - Improper handling of the username leads to a user enumeration attack vector in the backend login page.

  - A missing token check in the emailexport feature of com_privacy causes a CSRF vulnerability.

  - Lack of input validation while handling ACL rulesets can cause write ACL violations.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.joomla.org/announcements/release-news/5828-joomla-3-9-23.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b1cd937");
  # https://developer.joomla.org/security-centre/828-20201101-core-com-finder-ignores-access-levels-on-autosuggest.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?402c1f24");
  # https://developer.joomla.org/security-centre/829-20201102-core-disclosure-of-secrets-in-global-configuration-page.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1499a20");
  # https://developer.joomla.org/security-centre/830-20201103-core-path-traversal-in-mod-random-image.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f95e7c16");
  # https://developer.joomla.org/security-centre/831-20201104-core-sql-injection-in-com-users-list-view.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?999b82fe");
  # https://developer.joomla.org/security-centre/832-20201105-core-user-enumeration-in-backend-login.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34e3f080");
  # https://developer.joomla.org/security-centre/833-20201106-core-csrf-in-com-privacy-emailexport-feature.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba4d0911");
  # https://developer.joomla.org/security-centre/834-20201107-core-write-acl-violation-in-multiple-core-views.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c15bad3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.9.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/01");

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
  { 'min_version' : '1.7.0', 'max_version' : '3.9.22', 'fixed_version' : '3.9.23' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE, xsrf:TRUE});
