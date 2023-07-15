##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160884);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id("CVE-2022-0778", "CVE-2022-23943");

  script_name(english:"Tenable SecurityCenter 5.12.x - 5.18.x / 5.19.x / 5.20.x Multiple Vulnerabilities (TNS-2022-08)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 5.19.x or 5.20.x and is therefore affected by multiple vulnerabilities:
    
    - Read/write beyond bounds - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to
      overwrite heap memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 
      2.4.52 and prior versions. (CVE-2022-23943)
    
    - A denial of service (DoS) vulnerability exists in OpenSSL due to an infinite loop bug in the BN_mod_sqrt() function. 
      An unauthenticated, remote attacker can exploit this issue, via self-signed certificate, to trigger the loop during
      verification of the the certificate signature. (CVE-2022-0778)
  
Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-08");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-09");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2022041.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba44bb99");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory or upgrade to 5.21.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23943");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}


include('vcf_extras.inc');

var patches = make_list('SC-202204.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'min_version' : '5.12.0', 'fixed_version': '5.16.0', 'fixed_display' : 'Upgrade to 5.21.0 or later'},
  { 'min_version' : '5.16.0', 'fixed_version': '5.19.0', 'fixed_display' : 'Upgrade to at least 5.19.0 and apply patch SC-202204.1'},
  { 'min_version' : '5.19.0', 'max_version': '5.19.1', 'fixed_display'   : 'Apply Patch SC-202204.1'},
  { 'min_version' : '5.20.0', 'max_version' : '5.20.1', 'fixed_display'  : 'Apply Patch SC-202204.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
