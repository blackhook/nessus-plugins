#TRUSTED a8f4571acd92fc70bcabe04c147fb5c8a881b5952904fd9ced0b19f9e2303befca3596332e2b5c8c9b3d6d310955cef90b39fe5aae68675bbfe2956faab4ce7772d9a43f1fe0c4fcbe8d74611a42268048abb5002c90c0e88196b15ef67c33d36a4ed9ab7559a0b8ffc21d1603ab7176bb9c460ddb6e12eee8eabe798e860aca9b49846172b7994a400f80ef3a81928ff5ceeec29e4e459b19e30a4ecdf47c1b03107e2b230b7e02cf1d11e0d6a77c90ee16a19bde500ecc9e03302f21d3767932913a309e3168b57a3f290523be720353c97997a09cbdf88328f8524927ba13cf072ac2c512a1fe51fcdecc9ddad95da58f3990afddfc110a95cf9fc14adb2c24de7c8c096be8b2233b711c8131201e11b521562469d031a9292b3e8649f1a4dd7a81e5e93c7fcb71dd7396fe568fd7ada574644d82545a8a108c89e6ba8d57396a13f8cf59582207f6e4f3f976cbcda43ec238e53ab71d21dac7d8837bc7a5c9b03a2efcdd7ba593bc17477aabf5ac495c85079ba77ad1a304e4024639d8b7c9e1f7737a8750735175e5e0dceb0a33201560d3a0aab3a9d6b669e84417492e9405c0516eeae4b703771913155a1ca42ea58373b110e4176ee063e6e0dfd32b802f41cbd1d9db056464a436befa713ba088f7a99abfeb28ac121b99489b21979e01fb9a13632ad343a31cb7d0dc20e7a772e452f6c19629809cb4063065044b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142143);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id("CVE-2020-3299");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm69545");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-bypass-3eCfd24j");
  script_xref(name:"IAVA", value:"2020-A-0497");

  script_name(english:"Multiple Cisco Products SNORT HTTP Detection Engine File Policy Bypass (cisco-sa-ftd-bypass-3eCfd24j)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-ftd-bypass-3eCfd24j)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UTD SNORT IPS Engine Software is affected by a vulnerability. Please see
the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-bypass-3eCfd24j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb6dd6de");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm69545");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm69545");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:utd_snort_ips_engine");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Host/Cisco/Firepower");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.0.0',  'fix_ver': '6.3.0.1'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm69545',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
