#TRUSTED 33f01ceb9168fe0b8ce3f5818fe6e6cf27a5471d04b90bbefd66359cd486e40ae9f9fb370e5fff7c17f023ff30cdfcf37deb63f118cb5c2d858609c67efb5c5602a6fb5edb3f65e37583358a22e57cfed113977544444208919ff0830e8f696a928db33d31265340392af6c1e7e2e9f7cc9ae3824c6e39fb9cc5e129d3d1dda8cfd8ad7a10b580b8c3170f154619332792fb57230166405a234c0ead2a35e03add2515ec6b89060da1f589f5b7e661129f2f3ab7e3479ec51af32817118b4c1b7b2a0cf219a44a616b451ff4d7a3a9a2d36543fc8accf028e870f8d86906e569376737e35d1f280fb08d2c286397276083baa6483c59d3cbd9972b489e2eb84a903a2066dfccdf740d7fcf675534d45c5c80d6a5e755a31a120e27795300603ba8b570fb49f23aef1484b72100d8142236eacf219508964e6f393bdd1a5d2bd8dab8465e52699e03824f010200036c16439d07ba8f507b08b467e5628f4609e3dc44bd017078604461f31b0d576268b5ccdabb45156ab60457e735b9fd52738f46a75215f2ea3a1c55afa2be7ddba390d75979e0a015fad67aa8282dffcd0244b0fb63e974552325b5cb6e2427dee06a0b9009cf023135dc9776558f7afc3f8b10f5b5662c1caf8572838f0ace062c5fd1117f3c7a1dc47784da2dabadf939e387a43fc28ee47cb8619b64fa3f0d1300b9a010eeb170a1991b1c293b2435b3de
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140223);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3315");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt10151");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt28138");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort_filepolbypass-m4X5DgOP");

  script_name(english:"Multiple Cisco Products Snort HTTP Detection Engine File Policy Bypass (cisco-sa-snort_filepolbypass-m4X5DgOP)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by vulnerability in the Snort 
detection engine. The vulnerability is due to errors in how the Snort detection engine handles specific HTTP responses.
An unauthenticated, remote attacker can exploit this vulnerability by sending crafted HTTP packets that would flow 
through an affected system. A successful exploit could allow the attacker to bypass the configured file policies and 
deliver a malicious payload to the protected network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort_filepolbypass-m4X5DgOP
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff42201");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt10151");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt28138");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt10151");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version" , "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '16.12.4'}
];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt10151/CSCvt28138',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

