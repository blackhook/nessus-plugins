#TRUSTED 227d366c23d433989ea956a76e1fb220b46f68643003d76457853234e11b8647354629720bc54aad65aeba5ac6b42f08c8384c65567d22f68a7c78f1197ec7d10b030d7f1cbed6a5f76b7b2025f190a0cda61072e21d7c24df0b3b52485d8596a265cb8ecc4b2e38d62cc0bb38d4a37287e9bfcda124f65c684f4c45a84676b3efd5e1b85bc042d7049ddc0d3b267d2eb83983f99873165698144342791f1459941c43e6beea214b57ba4d73651bf9805bb45a02ab30213f33d903794f224c90e6a528c89658450859969edb8d7e97146dd44b89e917fe8c6659de0ed6b8f796d08e74102694add2ecce544c92cd3025e0e6a41c0ce3a535c7cb3d2d96538569fe23b67e2528d75872b3e7a9df5b3cbf08eae9b680d45ca795705be7b714f57bd347fd4187e7c0d844d6820f1928b6f20c5d46fcc89ede17b329b3de871b887b3d19ab522bea980b9892285526279020c61e87da708b890a9768cc6fe62e07208c222e5621b101a89d1f56149b12fd1549b9819d2d3cfcfbbd44c93d2b4e5f81793ef715310465cf1f5d76d1a237d877ee5759979bdc4bbdf805a5c6b71aad7ec165f862869dbd93239ccea1a4052cb5e3e7174d2cccc0f953a047a39414ec610c75357beb887fcaf924fe0dafce8b23d92359522f99119a87992aefcee09184682ec685d6d789b77e1892b729dd19f3e9d482da2dbe8618c79803d13352af44
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142493);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-26063");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07287");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv95114");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cimc-auth-zWkppJxL");
  script_xref(name:"IAVA", value:"2020-A-0502");

  script_name(english:"Cisco Integrated Management Controller Authorization Bypass (cisco-sa-cimc-auth-zWkppJxL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-cimc-auth-zWkppJxL)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System (Management Software) is affected by an
authorization bypass vulnerability due to improper authorization checks on API endpoints. An authenticate, remote
attacker can exploit this issue, by sending malicious requests to an API endpoint, to bypass authorization and take
actions on a vulnerable system without authorization.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-auth-zWkppJxL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78f235b6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv07287");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv95114");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv07287, CSCvv95114");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26063");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Unified Computing System (Management Software)");

# 4.0(4h)C and earlier
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '4.0(4h)D' }
];  

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv07287, CSCvv95114',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
