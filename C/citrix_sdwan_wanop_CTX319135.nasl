#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166618);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/28");

  script_cve_id("CVE-2021-22919");

  script_name(english:"Citrix SD-WAN WANOP Limitless Allocation (CTX319135)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a resource allocation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN WANOP device is version 10.2 before 10.2.9.b, 11.2 before 11.2.3.b, 11.3 before 11.3.2.a, or 
11.4 before 11.4.0.a. It is, therefore, affected by a resource allocation vulnerability that, if exploited, could lead
to the limited available disk space on the appliances being fully consumed.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX319135");
  script_set_attribute(attribute:"solution", value:
"Upgrade Citrix SD-WAN WAN-OS to version 10.2.9.b, 11.2.3.b, 11.3.2.a, 11.4.0.a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '10.2.0', 'fixed_version' : '10.2.9.b'},
  { 'min_version' : '11.2.0', 'fixed_version' : '11.2.3.b'},
  { 'min_version' : '11.3.0', 'fixed_version' : '11.3.2.a'},
  { 'min_version' : '11.4.0', 'fixed_version' : '11.4.0.a'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

