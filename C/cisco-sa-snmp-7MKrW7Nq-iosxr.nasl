#TRUSTED 6d45af4b5a55dbf64ec047c462814d9a266080325b363b7fc0ac68838e59ce3ab4f025021b80a7ff3d021eadd1536b914e53271e8f79a5aa0e1a9462bd84c340f495db644cd3f396365febdaa936ed79bd5b892ab3d2f06d0302e2b9d562d4a219c96f0dc942c110dd99a2f2f733aad925d29b828d2ba215ff5e30680ad6b07c771be6db34aba7ebdf11e61f48404f5505cee61429ba58577c983f241ca51034bddf835dd729e0ca7a4638be3f14a34cfc9c466f53c6f3ee22867597a984bf86cc3d6ef44e3c0816d4d340e6af9d6e6028270bc3bc1a6e2732ae2d4adc55cb4e3575b0dcb3b3cb9289661d07e5223cb3e133f3bf082f0a7f2100da29bb258ec9a20489b9388157a4ad5f6a91a044e2ac69a33068dde307cf9429daad0141577755aa36d2f23ba74ab7d1cfdbe7e2d1509f44fe7fad83200e326275219de7926eb2b1cba85d549292a77003c21581bee8f0eafc05fdd8beb5d0a747610f2a4fe9c5f1cd02155f70e0c3a29cea55990eabb05f7494a4ace30c0050e1b236cb850108244f0f3cc69986f1cc0bf1ab713053c4c179a27f1f1ae577403ee634ffde9914aa4e901ae9371d1e50557223fcce569606c112c13a874870951bd00094378747e1242fc2a06f4df89a873062f7687f857750b0375b0bdd9e6b96a757bf8cc7b20fd50eb293e8cd8008ff4917d1f401cdc31054f47fdbf34868d970bcf41ecd
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148320);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2021-1243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt93184");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-7MKrW7Nq");

  script_name(english:"Cisco IOS XR Software SNMP Management Plane Protection ACL Bypass (cisco-sa-snmp-7MKrW7Nq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by a security bypass vulnerability due to incorrect LPTS
programming when using SNMP with management plane protection. An unauthenticated, remote attacker can exploit this, by
connecting to an affected device with SNMP, to connect to the device on the configured SNMP ports despite having a
configuration to deny SNMP access. Valid credentials are required to execute any of the SNMP requests.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-7MKrW7Nq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a355528d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt93184");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt93184");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1243");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# Cannot cleanly check for vuln configuration + mitigations
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));
if (isnull(model))
  model = '';

smu_bid = 'CSCvt93184';

if ('ASR9K-PX' >< model || 'CRS-PX' >< model)
  smus['6.4.2'] = smu_bid;
else if ('NCS5500' >< model)
  smus['6.6.3'] = smu_bid;

vuln_ranges = [
  {'min_ver' : '6.1.1', 'fix_ver' : '6.6.4'},
  {'min_ver' : '6.7',   'fix_ver' : '6.7.2'},
  {'min_ver' : '7.1',   'fix_ver' : '7.1.1'},
  {'min_ver' : '7.2',   'fix_ver' : '7.2.1'}
];

# 7.0.x fixed version varies based on model
if ('NCS' >< model || 'ASR' >< model || 'XRV' >< model)
  append_element(var:vuln_ranges, value:{'min_ver' : '7.0',   'fix_ver' : '7.0.2'});
else
  append_element(var:vuln_ranges, value:{'min_ver' : '7.0',   'fix_ver' : '7.0.12'});

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt93184',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
