#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150865);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-8299");
  script_xref(name:"IAVA", value:"2021-A-0288-S");

  script_name(english:"Citrix SD-WAN Center Test Build Network DoS (CTX297155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center is version 10.2.x prior to 10.2.9a, 11.1.x prior to 11.1.2c, 11.2.x prior to 11.2.3a, 
or 11.2.x prior to 11.3.1a. It is, therefore, vulnerable to a Network-based denial-of-service from an attacker within 
the same Layer 2 network segment.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX285061");
  script_set_attribute(attribute:"solution", value:
"Upgrade Citrix SD-WAN Center to version 10.2.9a, 11.1.2c, 11.2.3a, 11.3.1a or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:citrix_sd-wan_cente");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN");

  exit(0);
}

include('vcf.inc');

var app_name = 'Citrix SD-WAN';
var app_info = vcf::get_app_info(app:app_name);

var edition = app_info['Edition'];
var model = app_info['Model'];
var pattern = "WAN-?OP";

if (!preg(pattern:pattern, string:app_info['Edition']) && !preg(pattern:pattern, string:app_info['Model']))
  audit(AUDIT_HOST_NOT, 'affected');

var constraints = [
  { 'min_version' : '11.3', 'fixed_version' : '11.3.1a' },
  { 'min_version' : '11.2', 'fixed_version' : '11.2.3a' },
  { 'min_version' : '11.1', 'fixed_version' : '11.1.2c' },
  { 'min_version' : '10.2', 'fixed_version' : '10.2.9a' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
 );
