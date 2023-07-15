##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163318);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/01");

  script_cve_id(
    "CVE-2022-25275",
    "CVE-2022-25276",
    "CVE-2022-25277",
    "CVE-2022-25278"
  );
  script_xref(name:"IAVA", value:"2022-A-0296-S");

  script_name(english:"Drupal 7.x < 7.91 / 9.3.x < 9.3.19 / 9.4.x < 9.4.3 Multiple Vulnerabilities (drupal-2022-07-20)");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 7.x prior to 7.91,
9.3.x prior to 9.3.19, or 9.4.x prior to 9.4.3. It is, therefore, affected by multiple vulnerabilities.

  - The Media oEmbed iframe route does not properly validate the iframe domain setting, which allows embeds to
    be displayed in the context of the primary domain. Under certain circumstances, this could lead to cross-
    site scripting, leaked cookies, or other vulnerabilities. This advisory is not covered by Drupal Steward.
    (CVE-2022-25276)

  - Updated 2022-07-20 19:45 UTC to indicate that this only affects Apache web servers. Drupal core sanitizes
    filenames with dangerous extensions upon upload (reference: SA-CORE-2020-012) and strips leading and
    trailing dots from filenames to prevent uploading server configuration files (reference: SA-
    CORE-2019-010). However, the protections for these two vulnerabilities previously did not work correctly
    together. As a result, if the site were configured to allow the upload of files with an htaccess
    extension, these files' filenames would not be properly sanitized. This could allow bypassing the
    protections provided by Drupal core's default .htaccess files and possible remote code execution on Apache
    web servers. This issue is mitigated by the fact that it requires a field administrator to explicitly
    configure a file field to allow htaccess as an extension (a restricted permission), or a contributed
    module or custom code that overrides allowed file uploads. (CVE-2022-25277)

  - Under certain circumstances, the Drupal core form API evaluates form element access incorrectly. This may
    lead to a user being able to alter data they should not have access to. No forms provided by Drupal core
    are known to be vulnerable. However, forms added through contributed or custom modules or themes may be
    affected. This advisory is not covered by Drupal Steward. (CVE-2022-25278)

  - In some situations, the Image module does not correctly check access to image files not stored in the
    standard public files directory when generating derivative images using the image styles system. Access to
    a non-public file is checked only if it is stored in the private file system. However, some contributed
    modules provide additional file systems, or schemes, which may lead to this vulnerability. This
    vulnerability is mitigated by the fact that it only applies when the site sets (Drupal 9)
    $config['image.settings']['allow_insecure_derivatives'] or (Drupal 7)
    $conf['image_allow_insecure_derivatives'] to TRUE. The recommended and default setting is FALSE, and
    Drupal core does not provide a way to change that in the admin UI. Some sites may require configuration
    changes following this security release. Review the release notes for your Drupal version if you have
    issues accessing files or image styles after updating. (CVE-2022-25275)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-015");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.3.19");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.3");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-014");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-010");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2020-012");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-013");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2022-012");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.91");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.91 / 9.3.19 / 9.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25277");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var port = get_http_port(default:80, php:TRUE);

var app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.91' },
  { 'min_version' : '9.3', 'fixed_version' : '9.3.19' },
  { 'min_version' : '9.4', 'fixed_version' : '9.4.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
