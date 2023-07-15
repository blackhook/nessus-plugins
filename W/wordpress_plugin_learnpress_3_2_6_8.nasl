#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136191);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-6010", "CVE-2020-11511");
  script_xref(name:"CEA-ID", value:"CEA-2020-0040");

  script_name(english:"WordPress Plugin 'LearnPress' < 3.2.6.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable to multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'LearnPress' plugin that is prior to 3.2.6.8
and, thus, is affected by multiple vulnerabilities :

  - A SQL injection (SQLi) vulnerability exists in the _get_items method of the LP_Modal_Search_Items class
    due to improper validation of user-supplied input. An authenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end database, resulting in the disclosure or manipulation of
    arbitrary data. (CVE-2020-6010)

  - A privilege escalation vulnerability exists in the learn_press_accept_become_a_teacher function due to the
    code not checking the permissions of the requesting user. An unauthenticated, remote attacker can exploit
    this, via /wpadmin/, to gain 'teacher' access to the application. (CVE-2020-11511)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://research.checkpoint.com/2020/e-learning-platforms-getting-schooled-multiple-vulnerabilities-in-wordpress-most-popular-learning-management-system-plugins/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b38b6cba");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/learnpress/#developers");
  script_set_attribute(attribute:"solution", value:
"Update the 'LearnPress' plugin to version 3.2.6.8 or later through the administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11511");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6010");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

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

app_info = vcf::wordpress::plugin::get_app_info(plugin:'learnpress');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'fixed_version' : '3.2.6.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{sqli:TRUE});
