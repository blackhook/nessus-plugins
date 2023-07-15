#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155559);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-41164", "CVE-2021-41165");
  script_xref(name:"IAVA", value:"2021-A-0559");

  script_name(english:"Drupal 8.9.x < 8.9.20 / 9.1.x < 9.1.14 / 9.2.x < 9.2.9 Multiple Vulnerabilities (drupal-2021-11-17)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 8.9.x prior to
8.9.20, 9.1.x prior to 9.1.14, or 9.2.x prior to 9.2.9. It is, therefore, affected by multiple vulnerabilities.

  - CKEditor4 is an open source WYSIWYG HTML editor. In affected versions a vulnerability has been discovered
    in the Advanced Content Filter (ACF) module and may affect all plugins used by CKEditor 4. The
    vulnerability allowed to inject malformed HTML bypassing content sanitization, which could result in
    executing JavaScript code. It affects all users using the CKEditor 4 at version < 4.17.0. The problem has
    been recognized and patched. The fix will be available in version 4.17.0. (CVE-2021-41164)

  - CKEditor4 is an open source WYSIWYG HTML editor. In affected version a vulnerability has been discovered
    in the core HTML processing module and may affect all plugins used by CKEditor 4. The vulnerability
    allowed to inject malformed comments HTML bypassing content sanitization, which could result in executing
    JavaScript code. It affects all users using the CKEditor 4 at version < 4.17.0. The problem has been
    recognized and patched. The fix will be available in version 4.17.0. (CVE-2021-41165)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-011");
  script_set_attribute(attribute:"see_also", value:"https://ckeditor.com/cke4/release/CKEditor-4.17.0");
  script_set_attribute(attribute:"see_also", value:"https://ckeditor.com/cke4/release/CKEditor-4.17.1");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ckeditor/ckeditor4");
  # https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-7h26-63m7-qhf2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93a11ed");
  # https://github.com/ckeditor/ckeditor4/security/advisories/GHSA-pvmx-g8h5-cprj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1789d069");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.20");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.1.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.2.9");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.9.20 / 9.1.14 / 9.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41165");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '8.9', 'fixed_version' : '8.9.20' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.14' },
  { 'min_version' : '9.2', 'fixed_version' : '9.2.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
