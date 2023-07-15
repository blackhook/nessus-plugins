#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118935);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-19207");

  script_name(english:"WordPress Plugin 'WP GDPR Compliance' < 1.4.3 Privilege Escalation");
  script_summary(english:"Checks version of WP GDPR Compliance plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable
to privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of
the 'WP GDPR Compliance' plugin that is prior to 1.4.3 and, thus, is
affected by a user-input validation error that can allow privilege
escalation attacks. Such attacks allow, among other actions, creation
of new administrator-level users.");
  script_set_attribute(attribute:"see_also", value:"https://www.wpgdprc.com/wp-gdpr-compliance-1-4-3-security-release/");
  # https://www.wordfence.com/blog/2018/11/trends-following-vulnerability-in-wp-gdpr-compliance-plugin/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e467f1d9");
  # https://www.wordfence.com/blog/2018/11/privilege-escalation-flaw-in-wp-gdpr-compliance-plugin-exploited-in-the-wild/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fc561db");
  # https://www.tenable.com/blog/new-wordpress-privilege-escalation-flaw-in-wp-gdpr-compliance-plugin
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bc767ef");
  script_set_attribute(attribute:"solution", value:
"Update the 'WP GDPR Compliance' plugin to version 1.4.3 or greater
through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::wordpress::plugin::get_app_info(plugin:"wp-gdpr-compliance");
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version" : "1.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
