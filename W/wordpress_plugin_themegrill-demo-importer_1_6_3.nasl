#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133856);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/21");

  script_name(english:"WordPress Plugin 'ThemeGrill Demo Importer' 1.3.4 < 1.6.3 Database Wipe and Auth Bypass");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has an outdated plugin installed
that contains a database wipe and auth bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has the
'ThemeGrill Demo Importer' plugin that is 1.3.4 or later, but
prior to 1.6.3. It is, therefore, vulnerable to an missing
authentication check that allows an unauthenticated user to
wipe the entire database to its default state and then
automatically be logged in as an administrator.");
  # https://www.webarxsecurity.com/critical-issue-in-themegrill-demo-importer/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55397bff");
  script_set_attribute(attribute:"solution", value:
"Update to ThemeGrill Demo Importer Plugin 1.6.3 or later or remove
the plugin through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of the vulnerability.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::wordpress::plugin::get_app_info(plugin:'themegrill-demo-importer');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '1.3.4', 'fixed_version' : '1.6.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
