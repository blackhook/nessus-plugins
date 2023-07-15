#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155961);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-20038",
    "CVE-2021-20039",
    "CVE-2021-20040",
    "CVE-2021-20041",
    "CVE-2021-20042",
    "CVE-2021-20043",
    "CVE-2021-20044",
    "CVE-2021-20045"
  );
  script_xref(name:"IAVA", value:"2021-A-0572");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/11");
  script_xref(name:"CEA-ID", value:"CEA-2021-0051");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"SonicWall Secure Mobile Access Multiple Vulnerabilities (SNWLID-2021-0026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall Secure Mobile Access is affected by multiple
vulnerabilities, including:

  - An unauthenticated stack-based buffer overflow due to the SonicWall SMA SSLVPN Apache httpd server GET method of
    mod_cgi module environment variables use a single stack-based buffer using `strcat`. This can allow a remote,
    unauthenticated attacker to execute arbitrary code. (CVE-2021-20038)

  - Multiple unauthenticated file explorer heap-based and stack-based buffer overflows due the sonicfiles RAC_COPY_TO
    (RacNumber 36) method which allows users to upload files to an SMB share and can be called without any
    authentication. This can allow a remote, unauthenticated attacker to execute arbitrary code as the nobody user.
    (CVE-2021-20045)

  - A heap-based buffer overflow due to the RAC_GET_BOOKMARKS_HTML5 (RacNumber 35) method that allows users to list
    their bookmarks. This method is vulnerable to heap-based buffer-overflow, due to unchecked use of strcat. This can
    allow a remote, authenticated attacker to execute arbitrary code as the nobody user. (CVE-2021-20043)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1e1dbee");
  # https://www.sonicwall.com/support/product-notification/product-security-notice-sma-100-series-vulnerability-patches-q4-2021/211201154715443/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01c34e29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.2.0.9-41sv or 10.2.1.3-27sv or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20044");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-20045");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SonicWall SMA 100 Series Authenticated Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sma_100_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app_name = 'SonicWall Secure Mobile Access';
var port = get_http_port(default:443,embedded:TRUE);
var app = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);

if (app['Model'] !~ "SMA (200|210|400|410|500v)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, port);

var constraints =
[
  {'min_version' : '9.0.0.0.0', 'max_version': '9.0.0.11.31', 'fixed_version' : '10.2.0.9.41', 'fixed_display':'Upgrade to version 10.2.0.9-41sv or later.'},
  {'min_version' : '10.2.0.0.0', 'max_version': '10.2.0.8.37', 'fixed_version' : '10.2.0.9.41', 'fixed_display':'Upgrade to version 10.2.0.9-41sv or later.'},
  {'min_version' : '10.2.1.0.0', 'max_version': '10.2.1.1.19', 'fixed_version' : '10.2.1.3.27', 'fixed_display':'Upgrade to version 10.2.1.3-27sv or later.'},
  {'min_version' : '10.2.1.2.0', 'max_version': '10.2.1.2.24', 'fixed_version' : '10.2.1.3.27', 'fixed_display':'Upgrade to version 10.2.1.3-27sv or later.'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
