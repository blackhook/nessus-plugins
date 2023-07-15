#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165701);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/05");

  script_name(english:"Dotnetnuke 6.0.x < 9.11.0 Multiple Vulnerabilities (09.11.00)");

  script_set_attribute(attribute:"synopsis", value:
"An ASP.NET application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Dotnetnuke running on the remote web server is 6.0.x prior to
9.11.0. It is, therefore, affected by multiple vulnerabilities.

  - A third-party dependency, Moment.js, published security updates to their library. Fixes for the Issue DNN
    Platform 9.11.0 upgrades this dependency to the latest version resolving all known security issues with
    this dependency at the time of release. Affected Versions 9.0.0 - 9.10.2 (2022-01)

  - DNN Platform utilizes a third-party WYSIWYG editor called CKEditor, this editor published numerous high-
    priority security issues. Fixes for the issue DNN Platform 9.11.0 has updated to CKE Version 4.18.0 and
    removed certain plugins to address various security bulletins. If you use other plugins than the provided
    ones, we suggest you check if they have updates available. Affected Versions. 8.0.0 - 9.10.2 (2022-02)

  - An issue existed where an authenticated user could craft a data payload allowing arbitrary execution of
    JavaScript code on a page of an installation in certain configurations. Fixes for the Issue DNN Platform
    9.11.0 introduced changes to the affected areas ensuring that all data display, as well as storage, is
    protected. Affected Versions 7.0.0 - 9.10.2 (2022-03)

  - A malicious user could craft a request that would execute a XSS payload within the Digital Assets Manager.
    Fix for the Issue The Digital Assets Manager module was removed from all installations in 9.11.0. Users
    that removed the Digital Asset Manager from older installations are protected from this issue. Affected
    versions 7.0.0 - 9.10.2 (2022-04)

  - jQuery and jQuery UI are utilized by DNN Platform, and both published multiple security bulletins. Fixes
    for the Issue JQuery and jQuery UI were updated to the latest versions in 9.11.0 Affected Versions 8.0.0 -
    9.10.2 (2022-05)

  - DNN Platform distributed a third-party extension for an editor that allowed a possible redirect to an
    untrusted destination. Fixes for the issue. The affected component was removed from DNN platform in
    version 9.11.0 Affected Versions 8.0.0 - 9.10.2 (2022-06)

  - DNN Platform utilizes KnockoutJS for portions of administrative functionality and new security
    vulnerabilities were noted by the publisher of the library. Fixes for the Issue DNN Platform 9.11.0 was
    updated to the latest version of knockout Affected Versions 9.0.0 - 9.10.2 (2022-07)

  - A DNN administrator functionally was erroneously allowing a stored credential to be viewable by other
    administrators. Fixes for issue DNN Platform 9.11.0 updated the interfaces to ensure no prior stored
    credentials could be viewed. Affected Versions 9.0.0 - 9.10.2 (2022-08)

  - DNN Platform uses Newtonsoft JSON for api serialization and the makers of this library published a high-
    priority security bulletin. Fixes for the Issue DNN Platform 9.11.0 was updated to the latest version.
    Affected Versions 6.0.0 - 9.10.2 (2022-09)

  - DNN Platform distributed and used SharpZipLib to provide File Compression functionality. The makers of
    this library published a high-priority security bulletin. Fixes for the Issue DNN Platform 9.11.0 was
    updated to the latest version. Affected Versions 6.0.0 - 9.10.2 (2022-10)

  - DNN Platform uses log4net for application logging and the makers of this library published a high priority
    security bulletin. Fixes for the Issue DNN Platform 9.11.0 was updated to the latest version. Affected
    Versions 6.0.0 - 9.10.2 (2022-11)

  - It was possible for a SuperUser to craft a request to obtain the contents of an arbitrary file in any
    directory of the DNN Platform installation. Fixes for the issue DNN Platform version 9.11.0 addressed this
    issue Affected Versions 9.0.0 - 9.10.2 (2022-12)

  - It was possible with a customized authentication provider to circumvent the logic traditionally completed
    upon application logging following a specific sequence of access. Fixes for the issue This issue was
    addressed in 9.11.0 by adjusting process flows. Affected Versions 7.4.2 - 9.10.2 (2022-13)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dotnetnuke version 9.11.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'DNN';

get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80, asp:TRUE);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '9.10.2', 'fixed_version' : '9.11.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
