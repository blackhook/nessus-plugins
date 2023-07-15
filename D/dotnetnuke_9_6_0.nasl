#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137055);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-19790");

  script_name(english:"Dotnetnuke 3.1.x < 9.6.0 / 5.0.x < 9.6.0 / 6.0.x < 9.6.0 / 7.0.x < 9.6.0 Multiple Vulnerabilities (09.06.00)");

  script_set_attribute(attribute:"synopsis", value:
"An ASP.NET application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Dotnetnuke running on the remote web server is 3.1.x prior to
9.6.0, 5.0.x prior to 9.6.0, 6.0.x prior to 9.6.0, or 7.0.x prior to 9.6.0. It is, therefore, affected by multiple
vulnerabilities.

  - Modules that were discarded to the recycle bin were
    still able to respond to API calls to their endpoints,
    which could result in data uploads and other
    interactions that would go unnoticed since the module
    was not visually displayed. Mitigating Factors This only
    impacted modules that are using the WebAPI interface
    following the DNN Security protocols (which is a smaller
    subset of modules). Additionally, interactions are still
    bound by all other security rules, as if the module was
    placed on the page. Fix(es) for This Issue An upgrade to
    DNN Platform version 9.5.0 or later is required Affected
    Versions DNN Platform Versions 6.0.0 through 9.4.4
    (2020-01)

  - A malicious user may be able to replace or update files
    with specific file extensions with content of their
    selection, without being authenticated to the website.
    Fix(es) for This Issue To remediate this issue an
    upgrade to DNN Platform Version (9.5.0 or later) is
    required. Affected Versions DNN Platform Versions 5.0.0
    through 9.6.0 Acknowledgements The DNN Community thanks
    the following for identifying the issue and/or working
    with us to help protect Users Robbert Bosker of
    DotControl Digital Creatives Related CVE: CVE-2019-19790
    (2020-02)

  - A number of older JavaScript libraries have been
    updated, closing multiple individual security notices.
    Fixes for the Issue Due to the nature of the elements
    included, and their usage with DNN Platform an upgrade
    to DNN Platform 9.5.0 or later is the only resolution
    for this issue.. Affected Versions DNN Platform version
    6.0.0 through 9.4.4 (2020-03)

  - A malicious user may upload a file with a specific
    configuration and tell the DNN Platform to extract the
    file. This process could overwrite files that the user
    was not granted permissions to, and would be done
    without the notice of the administrator. Fix(es) for
    This Issue The only proper fix for this issue is to
    upgrade to DNN Platform 9.6.0 or later. Affected
    Versions DNN Platform version 5.0.0 through 9.5.0. (It
    is believed this may affect 3.x and 4.x installations as
    well, but has not been verified) (2020-05)

  - A malicious user may utilize a process to include in a
    message a file that they might not have had the
    permission to view/upload, and with the methods that the
    DNN File system works they may be able to gain access to
    this file. Mitigating Factors Installations configured
    using the Secure folder type would not have the file
    contents disclosed. This is the recommended manner to
    guarantee file security for confidential documents as it
    is the only method that provides a secure file check at
    download. Fix(es) for This Issue Upgrading to DNN
    Platform version 9.6.0 or later is required to mitigate
    this issue. Acknowledgements The DNN Community would
    like to thank the following for their assistance with
    this issue. Connor Neff Affected Versions DNN Platform
    version 7.0.0 through 9.5.0. (2020-06)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2019-19790");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dotnetnuke version 9.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app = 'DNN';

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '3.1.0', 'max_version' : '9.5.0', 'fixed_version' : '9.6.0' },
  { 'min_version' : '5.0.0', 'max_version' : '9.5.0', 'fixed_version' : '9.6.0' },
  { 'min_version' : '6.0.0', 'max_version' : '9.5.0', 'fixed_version' : '9.6.0' },
  { 'min_version' : '7.0.0', 'max_version' : '9.5.0', 'fixed_version' : '9.6.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
