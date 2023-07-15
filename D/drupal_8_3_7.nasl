#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102714);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-6923", "CVE-2017-6924", "CVE-2017-6925");
  script_bugtraq_id(100368);

  script_name(english:"Drupal 8.x < 8.3.7 Multiple Vulnerabilities (SA-CORE-2017-004)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 8.x prior to 8.3.7. It is, therefore,
affected by multiple vulnerabilities :

  - A flaw exists in the views subsystem due to a failure to restrict
    access to the Ajax endpoint to only views configured to use Ajax.
    This is mitigated if you have access restrictions on the view.
    (CVE-2017-6923)

  - A flaw exists with REST API that allows users without the correct
    permission to post comments via REST that are approved even if the
    user does not have permission to post approved comments.
    (CVE-2017-6924)

  - A flaw exists in the entity access system that allows unwanted
    access to view, create, update, or delete entities. This only
    affects entities that do not use or do not have UUIDs, and
    entities that have different access restrictions on different
    revisions of the same entity. (CVE-2017-6925)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2017-08-16/drupal-core-multiple");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.3.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.3.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/24");

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
  { "min_version" : "8.0", "max_version" : "8.3.6", "fixed_version" : "8.3.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
