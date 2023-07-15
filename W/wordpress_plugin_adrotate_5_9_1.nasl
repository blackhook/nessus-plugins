#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168545);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/12");

  script_cve_id("CVE-2022-26366");
  script_xref(name:"IAVA", value:"2022-A-0489");

  script_name(english:"WordPress Plugin 'AdRotate Banner Manager' < 5.9.1 XSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that has a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'AdRotate Banner Manager' plugin that is
prior to 5.9.1. It is, therefore, affected by a cross-site request forgery (XSRF) vulnerability. A remote attacker
can, with the interaction of a privileged user, execute actions, such as a password change, under that user's
authentication.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://patchstack.com/database/vulnerability/adrotate/wordpress-adrotate-banner-manager-plugin-5-9-multiple-cross-site-request-forgery-csrf-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8318241c");
  script_set_attribute(attribute:"solution", value:
"Update the 'AdRotate Banner Manager' plugin to version 5.9.1 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adrotate_banner_manager_project:adrotate_banner_manager");
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

var app_info = vcf::wordpress::plugin::get_app_info(plugin:'adrotate');

var constraints = [
  { 'fixed_version': '5.9.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xsrf': TRUE}
);
