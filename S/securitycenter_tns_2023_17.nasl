##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(173739);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2023-25690");
  script_xref(name:"IAVA", value:"2023-A-0124");

  script_name(english:"Tenable SecurityCenter 5.22 - 6.0.0 Access Control Bypass (TNS-2023-17)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 5.22 to 6.0.0 and is therefore affected by an apache vulnerable which could result in bypassing of 
access controls.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-17");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#Tenable.sc-6.1.0-(2023-03-22)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c45a331");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202303.2');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
    { 'min_version' : '5.18.0', 'max_version': '5.23.1', 'fixed_display' : 'Apply Patch SC-202303.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
