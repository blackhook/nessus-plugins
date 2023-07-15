#TRUSTED 9e08e2a531a08558b148cd960a9837bc344372399813392c8aa33b4cd320d67f04f6388cc718171fd16ce6289a6ee01abc316b8bc0f28d8c7681aff45fb9dd936dbdffb81e20e2360f7ad023216ebd38fe1c49ac3f8dfed48e37af5cec3c109094ee00aae22fb7a2937f290ebc49a433e1069c63985e48d186f2419b95e196e2f831457f26c4181882da2031c9e30e095721dbc72d51fe290eb42873f60e2bc6194420d39c20455f07447add9d0596d851931c4d77a5acbf65c4ebef51e54896f353f878d855da3e5d8430e227ec7c8518844be69b57666dcbebe2e04c689169305a8d62a2134596e7b079504d30732f957425d6a9c08f7bb5a75981816e1f32928954777c20f49ecef176cad1a4eea45ddca2de43f787d381705750efb789493c5b7e9263ad35d6409fe6b85f299ba1fcb14c4659f8e6bdb94638b6f896beb36cae687bfce20c2ab2c497a9e5828b18e20d8f0e892736d40fc251708b2df68561e7266b54ef20673741d546f6aa82e0180d4f6d82960c2c2eeeb7bdb2f20ff44df520a236680a7f6422a02807236112447bb317e9acf2ed3f3efeba664884a175c2005bc7efda1cf3276c3a64864161d028fb8cfbe40627996afb5877c3fefdb4a659c6c89a8ec62bb21a22d6ec0a21a545fb811ddcbca0f939dcf318cca979caf29e2ed8e0c7a52790b448e57a1a306944a265bd8895671edaf18df979e6b3
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152936);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-1580", "CVE-2021-1581");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57577");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57581");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-mdvul-HBsJBuvW");
  script_xref(name:"IAVA", value:"2021-A-0403");

  script_name(english:"Cisco Application Policy Infrastructure Controller Multiple Vulnerabilities (cisco-sa-capic-mdvul-HBsJBuvW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller (APIC) is affected by multiple
vulnerabilities, including the following:
  
  - A command injection vulnerability exists in Cisco APIC due to invalid input validation. An authenticated,
    remote attacker can exploit this, by sending specially crafted requests, to execute arbitrary commands. 
    (CVE-2021-1580)

  - An arbitrary file upload vulnerability exists in Cisco APIC due to improper access control. An 
    unauthenticated, remote attacker can exploit this to upload arbitrary files on the remote host. 
    (CVE-2021-1581)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-mdvul-HBsJBuvW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c1c7a91");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57577");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57581");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw57577, CSCvw57581");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1580");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1581");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}
include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443); 
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10f)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(7l)'},
  {'min_ver': '5.0', 'fix_ver': '5.2(1g)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw57577, CSCvw57581',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
