#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136176);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-6008");
  script_xref(name:"CEA-ID", value:"CEA-2020-0040");

  script_name(english:"WordPress Plugin 'LifterLMS' < 3.37.15 Arbitrary File Write");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable to an arbitrary file write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'LifterLMS' plugin that is prior to 3.37.15
and, thus, is affected by an arbitrary file write vulnerability that can allow the attackers to write and execute
arbitrary PHP code on the server by changing their first name on their profile to PHP code.");
  # https://research.checkpoint.com/2020/e-learning-platforms-getting-schooled-multiple-vulnerabilities-in-wordpress-most-popular-learning-management-system-plugins/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b38b6cba");
  script_set_attribute(attribute:"see_also", value:"https://make.lifterlms.com/2020/03/30/lifterlms-version-3-37-15/");
  script_set_attribute(attribute:"solution", value:
"Update the 'LifterLMS' plugin to version 3.37.15 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::wordpress::plugin::get_app_info(plugin:'lifterlms');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '3.37.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
