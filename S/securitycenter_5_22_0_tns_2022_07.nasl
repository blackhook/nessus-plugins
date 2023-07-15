#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(163634);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2022-31129");
  script_xref(name:"IAVA", value:"2023-A-0059");

  script_name(english:"Tenable SecurityCenter < 5.22.0 Multiple Vulnerabilities (TNS-2022-15)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host 
has a third-party software vulnerability in Moment.js, prior to version 2.29.4. It contains a denial of service 
vulnerability due to an inefficient parsing algorithm. An remote attacker can pass a specially crafted 
large message into the application and cause a noticeable slowdown. 

Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-15");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-18");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2022091.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cba126f");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory or upgrade to 5.22.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202209.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
    { 'min_version' : '5.18.0', 'max_version': '5.21.0', 'fixed_display' : 'Apply Patch SC-202209.1 / Upgrade to 5.22.0 or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
