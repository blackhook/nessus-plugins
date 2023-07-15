#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107089);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-6926",
    "CVE-2017-6927",
    "CVE-2017-6930",
    "CVE-2017-6931"
  );
  script_bugtraq_id(103115, 103138);

  script_name(english:"Drupal 8.x < 8.4.5 Multiple Vulnerabilities (SA-CORE-2018-001)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 8.x prior to 8.4.5. It is, therefore,
affected by multiple vulnerabilities :

  - A flaw exists with the Comment Reply Form. An authenticated remote
    attacker could add or view comments that they do not have access
    to. (CVE-2017-6926)

  - A flaw exists with the Drupal.checkPlain() function due to
    improper handling of HTML injection. A remote attacker, with a
    specially crafted request, could potentially execute arbitrary
    script code within the trust relationship between the browser and
    server. (CVE-2017-6927)

  - A flaw exists with node access controls with a multilingual site
    due to defaulting to the untranslated version as a fallback. A
    remote attacker could potentially bypass access restrictions.
    (CVE-2017-6930)

  - A flaw exists with the Settings Tray module. A remote attacker
    could update data the do not have permission for. (CVE-2017-6931)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/SA-CORE-2018-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.4.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { "min_version" : "8.0", "fixed_version" : "8.4.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xss" : TRUE});
