#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171606);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id("CVE-2020-20633");

  script_name(english:"WordPress Plugin 'GDPR Cookie Consent' < 1.8.3 Multiple Vulnerabilities (CVE-2020-20633)");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'GDPR Cookie Consent' plugin that is
prior to 1.8.3. It is, therefore, affected by authenticated stored XSS and privilege escalation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://blog.nintechnet.com/wordpress-gdpr-cookie-consent-plugin-fixed-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16e0087f");
  script_set_attribute(attribute:"solution", value:
"Update the 'GDPR Cookie Consent' plugin to version 1.8.3 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-20633");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cookielawinfo:gdpr_cookie_consent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::wordpress::plugin::get_app_info(plugin:'cookie-law-info');

var constraints = [
  { 'fixed_version': '1.8.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss': TRUE}
);
