##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161505);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id("CVE-2022-29248");

  script_name(english:"Drupal 9.2.x < 9.2.20 / 9.3.x < 9.3.14 Drupal Vulnerability (SA-CORE-2022-010) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.2.x prior to 9.2.20
or 9.3.x prior to 9.3.14. It is, therefore, affected by a vulnerability.

  - Guzzle is a PHP HTTP client. Guzzle prior to versions 6.5.6 and 7.4.3 contains a vulnerability with the
    cookie middleware. The vulnerability is that it is not checked if the cookie domain equals the domain of
    the server which sets the cookie via the Set-Cookie header, allowing a malicious server to set cookies for
    unrelated domains. The cookie middleware is disabled by default, so most library consumers will not be
    affected by this issue. Only those who manually add the cookie middleware to the handler stack or
    construct the client with ['cookies' => true] are affected. Moreover, those who do not use the same Guzzle
    client to call multiple domains and have disabled redirect forwarding are not affected by this
    vulnerability. Guzzle versions 6.5.6 and 7.4.3 contain a patch for this issue. As a workaround, turn off
    the cookie middleware. (CVE-2022-29248)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-010");
  # https://github.com/guzzle/guzzle/security/advisories/GHSA-cwmx-hcrq-mhc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3278cd0");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/node/1173280");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.20");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 9.2.20 / 9.3.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/25");

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
  { 'min_version' : '9.2', 'fixed_version' : '9.2.20' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
