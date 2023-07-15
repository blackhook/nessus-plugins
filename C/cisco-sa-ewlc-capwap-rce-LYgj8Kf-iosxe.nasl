#TRUSTED 0c55b931ec46f03fb7f8d6126135d617b438a4748bb799752812978905443bec2430262bf743ee0cc90a8dd32a170bbb722e12d7cc6b1285dc125501dbb8e8c0e0be69204df8b440193ca8646affb7db8e6a8305c824b8498863aef709e3903186f9d446d04e6410779016ee6a0187b7263bea5ab0057cad7f7396b99f77b5aeb8d4f428e7a0642dd2c805ad12e2dabfe560cc46fbaeea7159a6da1005008702af6706e0f35419b407024c7e892b9b9655d41665509b3cc5b6848dddcd3583460b9414ef133a8ab9e30b81fc9f00585892c5cdeb9ee774f430b6800dc7028e20e203115ba6c0300b79cf517791ffa05f113a9129ec848d8d70ca20a4e6990fb2771a91bcbb66eeb2a28fe8e455797333a3e14bbe8050fea943b046bdc2f5dd819a8ddf3fc42dec57858303e3e5f5c825d552b82e4bb4ea1927dca5232cbc540a702d77ed2946f0efd7693e11534a1f424f467edf84e15b2a4107c7bb9fb0ac8d8c08e233826a2a37459238b6762b61e9303f664a70ce0ca5446aa4766101f3830a6d749cc6ea131bbb055bc9076815c96ccec520601ad88a8a969c5abb4ce9daf73f5bc1968f32d934f44e4d87dbc859c1f70b3b55d9bcb438d8e2228d074b1b380ff112164d37dd0c1720fc46f51ce9884011d0e0d03aca9dd7a200e9b34cecb64e265b1f4f217d13ac3aea543bb5ec2003f589c30cc8d8ffe1dfd98482c8ab
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153560);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id("CVE-2021-34770");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw08884");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-capwap-rce-LYgj8Kf");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution (cisco-sa-ewlc-capwap-rce-LYgj8Kf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of
    Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated,
    remote attacker to execute arbitrary code with administrative privileges or cause a denial of service
    (DoS) condition on an affected device. The vulnerability is due to a logic error that occurs during the
    validation of CAPWAP packets. An attacker could exploit this vulnerability by sending a crafted CAPWAP
    packet to an affected device. A successful exploit could allow the attacker to execute arbitrary code with
    administrative privileges or cause the affected device to crash and reload, resulting in a DoS condition.
    (CVE-2021-34770)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-rce-LYgj8Kf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8bccb0c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw08884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw08884");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);
    
# Vulnerable model list
if ('CATALYST' >!< model || model !~ '9300|9400|9500|9800|9800-CL')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.6.4s',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw08884',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
