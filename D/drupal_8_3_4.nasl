#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101063);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-6920", "CVE-2017-6921", "CVE-2017-6922");
  script_bugtraq_id(99211, 99219, 99222);

  script_name(english:"Drupal 7.x < 7.56 / 8.x < 8.3.4 Multiple Vulnerabilities (SA-CORE-2017-003)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 7.x prior to 7.56 or 8.x prior to 8.3.4.
It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the PECL YAML parser due to unsafe
    handling of PHP objects during certain operations. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-6920)

  - A flaw exists in the file REST resource due to improper
    validation of user-supplied input to multiple fields
    when manipulating files. An unauthenticated, remote
    attacker can exploit this to have an unspecified impact
    on integrity. Note that a site is only affected by this
    issue if it has the RESTful Web Services (rest) module
    enabled, the file REST resource is enabled and allows
    PATCH requests, and the attacker can get or register a
    user account on the site with permissions to upload
    files and to modify the file resource. (CVE-2017-6921)

  - An information disclosure vulnerability exists due to a
    failure to ensure that private files that have been
    uploaded by an anonymous user but not permanently
    attached to content on the site are only visible to the
    anonymous user who uploaded them instead of all
    anonymous users. An unauthenticated, remote attacker can
    exploit this to disclose the files of other anonymous
    users. (CVE-2017-6922)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2017-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.56");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.3.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.56 / 8.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6920");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "7.0", "max_version" : "7.55", "fixed_version" : "7.56" },
  { "min_version" : "8.0", "max_version" : "8.3.3", "fixed_version" : "8.3.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
