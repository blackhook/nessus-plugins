#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136286);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-6009");
  script_xref(name:"CEA-ID", value:"CEA-2020-0040");

  script_name(english:"WordPress Plugin 'LearnDash' < 3.1.6 SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable to a SQL Injection (SQLi) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'LearnDash' plugin that is prior to 3.1.6
and, thus, is affected by a SQL Injection (SQLi) exists in the 'learndash_get_course_groups' function in the
ld-groups.php file due to improper validation of user-supplied input. An unauthenticated, remote attacker can exploit
this to inject or manipulate SQL queries in the back-end database, resulting in the disclosure or manipulation of
arbitrary data.");
  # https://research.checkpoint.com/2020/e-learning-platforms-getting-schooled-multiple-vulnerabilities-in-wordpress-most-popular-learning-management-system-plugins/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b38b6cba");
  script_set_attribute(attribute:"see_also", value:"https://learndash.releasenotes.io/release/YBfaq-version-316");
  script_set_attribute(attribute:"solution", value:
"Update the 'LearnDash' plugin to version 3.1.6 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6009");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:learndash:learndash");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_learndash_detect.nbin");
  script_require_keys("installed_sw/LearnDash");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:"LearnDash", port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '3.1.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE});
