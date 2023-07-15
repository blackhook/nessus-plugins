#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159487);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-20028");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"SonicWall Secure Mobile Access (SMA) SQLi (SNWLID-2021-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SonicWall Secure Mobile Access (SMA) device that is affected by an SQL injection
vulnerability due to improper neutralization of an SQL command. An unauthenticated, remote attacker can exploit this
to run SQL commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a SonicWall SMA version that is 9.0.0.10-28sv or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20028");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sma_100_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:mobile_access_firmware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

var port = get_http_port(default:443, embedded:TRUE);

var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

var constraints = [
  {'min_version' : '8.0', 'max_version' : '9.0.0.9.26', 'fixed_display' : '9.0.0.10-28sv and higher'}

];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'sqli':TRUE}
);
