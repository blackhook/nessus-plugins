#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132340);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Drupal 7.0.x < 7.69 / 8.7.x < 8.7.11 / 8.8.x < 8.8.1 Multiple Vulnerabilities (drupal-2019-12-18)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.0.x prior to 7.69,
8.7.x prior to 8.7.11, or 8.8.x prior to 8.8.1. It is, therefore, affected by multiple vulnerabilities.

  - The Drupal project uses the third-party library
    Archive_Tar, which has released a security update that
    impacts some Drupal configurations. Multiple
    vulnerabilities are possible if Drupal is configured to
    allow .tar, .tar.gz, .bz2 or .tlz file uploads and
    processes them. The latest versions of Drupal update
    Archive_Tar to 1.4.9 to mitigate the file processing
    vulnerabilities. (SA-CORE-2019-012)

  - The Media Library module has a security vulnerability
    whereby it doesn't sufficiently restrict access to media
    items in certain configurations. (SA-CORE-2019-011)

  - Drupal 8 core's file_save_upload() function does not
    strip the leading and trailing dot ('.') from filenames,
    like Drupal 7 did. Users with the ability to upload
    files with any extension in conjunction with contributed
    modules may be able to use this to upload system files
    such as .htaccess in order to bypass protections
    afforded by Drupal's default .htaccess file. After this
    fix, file_save_upload() now trims leading and trailing
    dots from filenames. (SA-CORE-2019-010)

  - A visit to install.php can cause cached data to become
    corrupted. This could cause a site to be impaired until
    caches are rebuilt. (SA-CORE-2019-009)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.69");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.7.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.8.1");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-009");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-010");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-011");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-012");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.69 / 8.7.11 / 8.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.69' },
  { 'min_version' : '8.7.0', 'fixed_version' : '8.7.11' },
  { 'min_version' : '8.8.0', 'fixed_version' : '8.8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
