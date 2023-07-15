##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162621);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-28614", "CVE-2022-28615", "CVE-2022-31813");

  script_name(english:"Tenable SecurityCenter 5.19.x / 5.20.x / 5.21.0 Multiple Vulnerabilities (TNS-2022-14)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 
running 5.19.x, 5.20.x, or 5.21.0 and is therefore affected by multiple vulnerabilities:
    
    - The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read unintended memory if an 
      attacker can cause the server to reflect very large input using ap_rwrite() or ap_rputs(), such as 
      with mod_luas r:puts() function. Modules compiled and distributed separately from Apache HTTP Server
      that use the 'ap_rputs' function and may pass it a very large (INT_MAX or larger) string must be 
      compiled against current headers to resolve the issue. (CVE-2022-28614)
    
    - Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds 
      in ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed 
      with the server can be coerced into such a call, third-party modules or lua scripts that use 
      ap_strcmp_match() may hypothetically be affected. (CVE-2022-28615)

    - Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server 
      based on client side Connection header hop-by-hop mechanism. This may be used to bypass IP based 
      authentication on the origin server/application. (CVE-2022-31813)
  
Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-14");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2022061.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6698356");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202206.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'min_version' : '5.12.0', 'fixed_version': '5.16.0', 'fixed_display' : 'Upgrade to 5.21.0 or later'},
  { 'min_version' : '5.16.0', 'fixed_version': '5.19.0', 'fixed_display' : 'Upgrade to at least 5.19.0 and apply patch SC-202206.1'},
  { 'min_version' : '5.19.0', 'max_version': '5.19.1', 'fixed_display'   : 'Apply Patch SC-202206.1'},
  { 'min_version' : '5.20.0', 'max_version' : '5.20.1', 'fixed_display'  : 'Apply Patch SC-202206.1' },
  { 'min_version' : '5.21.0', 'max_version' : '5.21.0', 'fixed_display'  : 'Apply Patch SC-202206.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);