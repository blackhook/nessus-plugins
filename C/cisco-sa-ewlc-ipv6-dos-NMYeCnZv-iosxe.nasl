#TRUSTED a9654343d114e4a7a82da82bdc6cf680bf0143422d24a9d084d545cc8b77574b17d92dc83cb79161df37f83f9b6b72fcae7b5629cceff5baba874b67fd959adde02b43ee07104f27b59c3e7d876159943e91ce21ad3a13155417ad7ead4c4d42e88498fd9486bba760e85f70d03fffa02586bf9f2590505592029c456cf207d78497f2f2627aa5a22892db179dedee776460166248e832a34f5994b88f6a9f88a308e876fdce278e4c42f61bc22f2beb494f1220de0c6f51cb22da5ce9ea880f9257d154a0dcef6e40325c16a497c515f1a2949fd4dd3593a62b60512b1c6ad170c8e985350a65774296d7cc951fc94477aa99b396a2eb1c08639de5b581fb4bc068a285a101a28d31edca4eba8ed914b1288e91388aa0c42eb221a937c20eb203e84775c03c0475c29b61fe7f0970723fbd07a5d0997dc73379c302cfc34ef77c9e7524115a7533cde217c35e1257a56e7634329ff02ba7524a6d7810984938c30ddb29c37b9bdc207f384296581f0988d048650080b28f7af8bb037ea8f78007aa31a6b1f209047a9076ed90f7a484c426554968a921024eb07e2a41296aabccd245efc17d32d796d6806a9d5ff980408b28588ad5cab3b2ef71a22ff82735831e85117939388b6292e6a4a882236d79a1ccb2e2bcc6641fc3e783031fe6ddbc1d898815bf3b926aab7da2594ce93cff4d7e6d7f4f7478215054447bf481d2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153561);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/15");

  script_cve_id("CVE-2021-34767");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw18506");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-ipv6-dos-NMYeCnZv");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software for Catalyst 9800 Series Wireless Controllers IPv6 Denial of Service (cisco-sa-ewlc-ipv6-dos-NMYeCnZv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in IPv6 traffic processing of Cisco IOS XE Wireless Controller Software for Cisco Catalyst
    9000 Family Wireless Controllers could allow an unauthenticated, adjacent attacker to cause a Layer 2 (L2)
    loop in a configured VLAN, resulting in a denial of service (DoS) condition for that VLAN. The
    vulnerability is due to a logic error when processing specific link-local IPv6 traffic. An attacker could
    exploit this vulnerability by sending a crafted IPv6 packet that would flow inbound through the wired
    interface of an affected device. A successful exploit could allow the attacker to cause traffic drops in
    the affected VLAN, thus triggering the DoS condition. (CVE-2021-34767)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-ipv6-dos-NMYeCnZv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6ce85af");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw18506");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw18506");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34767");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(670);

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
if ('CATALYST' >!< model && model !~ '9800')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvw18506',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
