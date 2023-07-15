#TRUSTED 4c5c454042ba1ac97dc53c3867904a13e6af936e8f55f70f773d15612e8c1c86e4c28cdfb9acd6cefbfaef2eb3418ce7702420a34406ce413a396090c9e0b2f991baddc4a09634a876905ce2151ea5487e53d416578c75610eb940f7ebb875c6707e6df1601db569f1596476640a0bdd35cae317abbaa21114cd55f654c953552c941a30156a4b72f89988a5a302317131402a2cb41032d1f17b439839c2b95c7411a8b34decbea9be7b37020d317e139ec3fc91f76aaf4f7e79e51183ac0fadc3ceab28491987ee0665c23fe259c33b6e431c2b13fa9ae0636b443790d8498aee128cd71b332928d2eea206e0885f5fea18e7bfdb4897ca4fec4f13ff0a54ae9b03f986798434fef7b67d1721a20cc3af761162d57c731144d2d0f8e8f267ad1845bc8cc78ef833f47670b3c582448bfd3c1c69c3a35aa01be5d0fe5dbc203206311150bd67383e6b48e79df45d6e8cc6384c9b686d4c40f2b9372bd8a255d5a5dbb217c54df6a4b60c0cdd36da07588e6e00f37d486dfaaa69ecfdc2cd84f90719bf2ff156d0861fe5f7ef0110e80c9971b4beffe8a0df4fe50dc9a45bdc6d0111b035b720f72dd8614574349dc58bb4df717d6137ae0daee0345dd983c4d07320cd226f484fec989cca8e43b5d62efc60dfa8d0462f8b93e8365489c19158c61dcfe45b74b9f04ffb19f6e649fe7b044dc1a76968b173e1a7bc8d5aa81e8e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153154);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1385");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21776");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21783");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-pt-hWGcPf7g");

  script_name(english:"Cisco IOS Software IOx Application Environment Path Traversal (cisco-sa-iox-pt-hWGcPf7g)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

  - A vulnerability in the Cisco IOx application hosting environment of multiple Cisco platforms could allow
    an authenticated, remote attacker to conduct directory traversal attacks and read and write files on the
    underlying operating system or host system. This vulnerability occurs because the device does not properly
    validate URIs in IOx API requests. An attacker could exploit this vulnerability by sending a crafted API
    request that contains directory traversal character sequences to an affected device. A successful exploit
    could allow the attacker to read or write arbitrary files on the underlying operating system.
    (CVE-2021-1385)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-pt-hWGcPf7g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?529bd81f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21776");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21783");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw64810, CSCvx21776, CSCvx21783");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var version_list=make_list(
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M4',
  '15.8(3)M5',
  '15.8(3)M6',
  '15.9(3)M',
  '15.9(3)M1',
  '15.9(3)M2',
  '15.9(3)M2a',
  '15.9(3)M3'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['ios_iox_host_list'],
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw64810, CSCvx21776, CSCvx21783',
  'cmds'     , make_list('show iox host list detail', 'show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
