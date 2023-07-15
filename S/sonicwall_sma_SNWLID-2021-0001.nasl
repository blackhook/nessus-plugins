#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146091);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-20016");
  script_xref(name:"IAVA", value:"2021-A-0065-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0006");

  script_name(english:"SonicWall Secure Mobile Access Remote Code Execution (SNWLID-2021-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall Secure Mobile Access is affected by a remote code
execution vulnerability. An unauthenticated, remote attacker can exploit this to bypass authentication and execute
arbitrary commands. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5956a722");
  # https://www.sonicwall.com/support/product-notification/urgent-patch-available-for-sma-100-series-10-x-firmware-zero-day-vulnerability-updated-feb-3-2-p-m-cst/210122173415410/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?421bba7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.2.0.5-29sv or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20016");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

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
  {'min_version' : '10.0', 'fixed_version' : '10.2.0.5.29', 'fixed_display':'Upgrade to version 10.2.0.5-29sv or later.'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE);
