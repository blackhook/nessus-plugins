#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167867);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-40696");
  script_xref(name:"IAVA", value:"2022-A-0489");

  script_name(english:"WordPress Plugin 'Advanced Custom Fields' < 5.12.4, 6.x < 6.0.3 Custom Field Value Exposure");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that has a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'Advanced Custom Fields' plugin that is prior
to 5.12.4 or 6.x prior to 6.0.3. It is, therefore, affected by a custom field value exposure through parsed shortcode
from user input vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.advancedcustomfields.com/blog/acf-6-0-3-release-security-changes-to-the-acf-shortcode-and-ui-improvements/#acf-shortcode
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?255a7a12");
  # https://patchstack.com/database/vulnerability/advanced-custom-fields/wordpress-advanced-custom-fields-plugin-3-1-1-6-0-2-custom-field-value-exposure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fa827cd");
  script_set_attribute(attribute:"solution", value:
"Update the 'Advanced Custom Fields' plugin to version 5.12.4, 6.0.3 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40694");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::wordpress::plugin::get_app_info(plugin:'advanced-custom-fields');
vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '3.1.1', 'fixed_version': '5.12.4' },
  { 'min_version' : '6.0', 'fixed_version': '6.0.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
