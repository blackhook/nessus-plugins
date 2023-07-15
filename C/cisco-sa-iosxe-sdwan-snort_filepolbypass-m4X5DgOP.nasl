#TRUSTED 60f39a3bed6b8fc966b72ce54e011e2f269c11887995f929cb4338ce7b739c445024833de8401711b64bccfd3f8934e7aeffcc3cd86aa824b13fbc0f8fae6dbf79e2b358ea67e7c3294521c45e211676429aac93b1d5f46f00f3bb4abdd14185593464043e75bc397e3b977633c67cb787dc575ebcba90bd63eb0e53bf73215996b9f5ed988bba6f8390d590229909cb77f79271ee40af1c1b6ea8a3a72c2c792a0b6fd46f24f3afd384179c4dde2b8558007c330c57f67b244f09f03cba0256db9e1b8c9fc18164179a26d44492fd673d4f45260b2275d3b321b1a285cdae80d1f332905dc1adfbd138bddf9bcc9e19c41e85117cbc70ebc909f5b3b5e7e24ed82e8e0092a9922d89ac76a6dd7e21f5d0d376827e8d31da832913eaf77d60e2dc35778298a72b7edd88832c7e133aeddba959276c93485264af37858db2df291a9315433a045b9fa55c00c22cdb8856ee3fbd96c7bef7c5b1d866bbe625da5a5c75bb01e9fdd94809c57b025d425640ce6ae1fe8f8980db19ee66e25c75360d2954ce0a35613255073e73e7d5ac92465a704a89d6d8e0fd94c8f022600ac68f58879c9af8890155de86e7411a3336a2e23b50d4fff5673983563c4bf2f9c5d2ab6c57e1ed862b667cd62b1f875413f34a495a10238143d6402766743631a6e597a61476524bd8686a223499067557479bc4b49e25a8965729dec26bdd695552
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140222);
  script_version("1.8");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '99999'}
];

var model_check = tolower(product_info['model']);

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt10151/CSCvt28138',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

