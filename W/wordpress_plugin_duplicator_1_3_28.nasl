#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133846);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-11738");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"WordPress Plugin 'Duplicator' < 1.3.28 Unauthenticated Arbitrary File Download");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable
to unauthenticated arbitrary file download.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of
the 'Duplicator' plugin that is prior to 1.3.28 and, thus, is
affected by an unauthenticated arbitrary file download vulnerability that can allow
the attackers to download 'wp-config.php' and steal database credentials.");
  # https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f2901d0");
  script_set_attribute(attribute:"solution", value:
"Update the 'Duplicator' plugin to version 1.3.28 or greater
through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11738");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress Duplicator < 1.3.28 Directory Traversal");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::wordpress::plugin::get_app_info(plugin:'duplicator');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version': '1.0.0', 'max_version': '1.3.26', 'fixed_version' : '1.3.28' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

