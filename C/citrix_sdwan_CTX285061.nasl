##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142894);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/18");

  script_cve_id("CVE-2020-8271", "CVE-2020-8272", "CVE-2020-8273");
  script_xref(name:"IAVA", value:"2020-A-0524-S");

  script_name(english:"Citrix SD-WAN Center 10.2.x < 10.2.8 / 11.1.x < 11.1.2b / 11.2.x < 11.2.2 Multiple Vulnerabilities (CTX285061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center is version 10.2.x prior to 10.2.8, 11.1.x prior to 11.1.2b, 11.2.x prior to
11.2.2. It is, therefore, affected by multiple vulnerabilities:

  - An unauthenticated remote code execution with root privileges. (CVE-2020-8271)

  - A authentication bypass resulting in exposure of SD-WAN functionality. (CVE-2020-8272)

  - A privilege escalation of an authenticated user to root. (CVE-2020-8273)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX285061");
  script_set_attribute(attribute:"solution", value:
"Upgrade Citrix SD-WAN Center to version 10.2.8, 11.1.2b, 11.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(23, 78, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN");

  exit(0);
}

include('vcf.inc');
include('http.inc');

app_name = 'Citrix SD-WAN';

port = get_http_port(default:443);

app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

edition = app_info['Edition'];

if (report_paranoia < 2 && empty_or_null(edition))
  audit(AUDIT_PARANOID);

if (!empty_or_null(edition) && 'center' >!< tolower(edition))
  audit(AUDIT_HOST_NOT, 'affected');

constraints = [
  { 'min_version' : '10.2.0', 'fixed_version' : '10.2.8' },
  { 'min_version' : '11.1.0', 'fixed_version' : '11.1.2b' },
  { 'min_version' : '11.2.0', 'fixed_version' : '11.2.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
