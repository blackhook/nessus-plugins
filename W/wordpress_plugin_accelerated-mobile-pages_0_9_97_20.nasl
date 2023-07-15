#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118977);
  script_version("1.2");
  script_cvs_date("Date: 2018/11/16 15:19:25");

  script_name(english:"WordPress Plugin 'AMP for WP - Accelerated Mobile Pages' < 0.9.97.20 Multiple Vulnerabilities");
  script_summary(english:"Checks version of  AMP for WP plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of
the 'AMP for WP - Accelerated Mobile Pages' plugin that is prior to
0.9.97.20 and, thus, is affected by multiple vulnerabilities. The most
severe of which would allow a low level user to modify any request to
call AJAX hooks and insert malicious code into a site. The patched
version also corrects flaws for cross-site scripting (XSS)
vulnerabilities as well as other precautionary fixes.");
  script_set_attribute(attribute:"see_also", value:"https://www.webarxsecurity.com/amp-plugin-vulnerability/");
  script_set_attribute(attribute:"see_also", value:"https://thehackernews.com/2018/11/amp-plugin-for-WordPress.html");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/accelerated-mobile-pages/");
  script_set_attribute(attribute:"see_also", value:"https://ampforwp.com/0-9-97-20-released-stability-update/");
  script_set_attribute(attribute:"solution", value:
"Update the 'AMP for WP - Accelerated Mobile Pages' plugin to
version 0.9.97.20 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::wordpress::plugin::get_app_info(plugin:"accelerated-mobile-pages");
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version" : "0.9.97.20" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xss":TRUE});
