##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162123);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_cve_id("CVE-2022-31042", "CVE-2022-31043");

  script_name(english:"Drupal 9.2.x < 9.2.21 / 9.3.x < 9.3.16 Drupal Multiple Vulnerabilities (SA-CORE-2022-011) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.2.x prior to 9.2.21,
9.3.x prior to 9.3.16 or 9.4.x prior to 9.4.0-rc2. It is, therefore, affected by multiple vulnerabilities.

- Guzzle is an open source PHP HTTP client. In affected versions the `Cookie` headers on requests are
sensitive information. On making a request using the `https` scheme to a server which responds with a
redirect to a URI with the `http` scheme, or on making a request to a server which responds with a
redirect to a a URI to a different host, we should not forward the `Cookie` header on. Prior to this fix,
only cookies that were managed by our cookie middleware would be safely removed, and any `Cookie` header
manually added to the initial request would not be stripped. We now always strip it, and allow the cookie
middleware to re-add any cookies that it deems should be there. Affected Guzzle 7 users should upgrade to
Guzzle 7.4.4 as soon as possible. Affected users using any earlier series of Guzzle should upgrade to
Guzzle 6.5.7 or 7.4.4. Users unable to upgrade may consider an alternative approach to use your own
redirect middleware, rather than ours. If you do not require or expect redirects to be followed, one
should simply disable redirects all together. (CVE-2022-31042)

- Guzzle is an open source PHP HTTP client. In affected versions `Authorization` headers on requests are
sensitive information. On making a request using the `https` scheme to a server which responds with a
redirect to a URI with the `http` scheme, we should not forward the `Authorization` header on. This is
much the same as to how we don't forward on the header if the host changes. Prior to this fix, `https` to
`http` downgrades did not result in the `Authorization` header being removed, only changes to the host.
Affected Guzzle 7 users should upgrade to Guzzle 7.4.4 as soon as possible. Affected users using any
earlier series of Guzzle should upgrade to Guzzle 6.5.7 or 7.4.4. Users unable to upgrade may consider an
alternative approach which would be to use their own redirect middleware. Alternately users may simply
disable redirects all together if redirects are not expected or required. (CVE-2022-31043)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-011");
  # https://github.com/guzzle/guzzle/security/advisories/GHSA-f2wf-25xc-69c9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?480a85b9");
  # https://github.com/guzzle/guzzle/security/advisories/GHSA-w248-ffj2-4v5q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67250a58");
  # https://www.drupal.org/docs/develop/using-composer/manage-dependencies#s-moving-from-drupalcore-recommended-to-drupalcore
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8d24d6d");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/1173280");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/3268032");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.21");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.16");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.0-rc2");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.2.21 / 9.3.16 / 9.4.0-rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31043");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '9.2', 'fixed_version' : '9.2.21' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.16' },
  { 'min_version' : '9.4-rc0', 'fixed_version': '9.4.0-rc2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
