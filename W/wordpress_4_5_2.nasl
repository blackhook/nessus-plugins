#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91101);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id(
    "CVE-2016-3714",
    "CVE-2016-3715",
    "CVE-2016-3716",
    "CVE-2016-3717",
    "CVE-2016-3718",
    "CVE-2016-4566",
    "CVE-2016-4567"
  );
  script_bugtraq_id(
    89848,
    89849,
    89852,
    89861,
    89866,
    90300
  );
  script_xref(name:"CERT", value:"250519");
  script_xref(name:"EDB-ID", value:"39767");
  script_xref(name:"EDB-ID", value:"39791");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"WordPress < 4.5.2 Multiple Vulnerabilities (ImageTragick)");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the WordPress
application running on the remote web server is prior to 4.5.2.
It is, therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability, known as
    ImageTragick, exists in the ImageMagick library due to a
    failure to properly filter shell characters in filenames
    passed to delegate commands. A remote attacker can
    exploit this, via specially crafted images, to inject
    shell commands and execute arbitrary code.
    (CVE-2016-3714)

  - An unspecified flaw exists in the ImageMagick library in
    the 'ephemeral' pseudo protocol that allows an attacker
    to delete arbitrary files. (CVE-2016-3715)

  - An unspecified flaw exists in the ImageMagick library in
    the 'ms' pseudo protocol that allows an attacker to move
    arbitrary files to arbitrary locations. (CVE-2016-3716)

  - An unspecified flaw exists in the ImageMagick library in
    the 'label' pseudo protocol that allows an attacker, via
    a specially crafted image, to read arbitrary files.
    (CVE-2016-3717)

  - A server-side request forgery (SSRF) vulnerability
    exists due to an unspecified flaw related to request
    handling between a user and the server. A remote
    attacker can exploit this, via an MVG file with a
    specially crafted fill element, to bypass access
    restrictions and conduct host-based attacks.
    (CVE-2016-3718)

  - An unspecified flaw exists in Plupload that allows an
    attacker to perform a same-origin method execution.
    (CVE-2016-4566)

  - A reflected cross-site scripting vulnerability exists in
    MediaElement.js due to improper validation of
    user-supplied input. A context-dependent attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2016-4567)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2016/05/wordpress-4-5-2/");
  script_set_attribute(attribute:"see_also", value:"https://imagetragick.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3714");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "WordPress";
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version":"3.7.14", "fixed_display" : "3.7.14 / 4.5.2" },
  { "min_version":"3.8", "fixed_version":"3.8.14", "fixed_display" : "3.8.14 / 4.5.2" },
  { "min_version":"3.9", "fixed_version":"3.9.12", "fixed_display" : "3.9.12 / 4.5.2" },
  { "min_version":"4.0", "fixed_version":"4.0.11", "fixed_display" : "4.0.11 / 4.5.2" },
  { "min_version":"4.1", "fixed_version":"4.1.11", "fixed_display" : "4.1.11 / 4.5.2" },
  { "min_version":"4.2", "fixed_version":"4.2.8", "fixed_display" : "4.2.8 / 4.5.2" },
  { "min_version":"4.3", "fixed_version":"4.3.4", "fixed_display" : "4.3.4 / 4.5.2" },
  { "min_version":"4.4", "fixed_version":"4.4.3", "fixed_display" : "4.4.3 / 4.5.2" },
  { "min_version":"4.5", "fixed_version":"4.5.2", "fixed_display" : "4.5.2" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
