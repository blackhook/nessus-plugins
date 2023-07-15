#TRUSTED 5d183311573875c9853d7e4f1b07a429e4413f5ad8f2572e40d5cf93051cd87577f6cc2c0330f936955a16d279b2473e8b2cfa3aeaef0c6aab6e1ed04432ae2535f2a228fb151ea4178bf57d508b35fb215d922d9621240e377d346d7b7f3213b615bd9223a96fec5ca25d6960838de64fd9e5d28c99359d6670e84b4243b29fa473f87940a378c3df3b66d5ec45f87af8c2fdfd8ec589b417af161a62d53fd9e4779077786ed08bffeef43112f5cc55c8ada8dbcafe7b469f999dad01d3271f607ad3b6635b6162960f8f34afdc546a060f84843940e3b75180030fcf2273fc91d924d4033c9b8f5820ab3c9dfada3a95bfe6a1ffd9d546094cef8ac976103ff4790fada6ff02ad135b351c0461f4165796fdce3d883d1af90d10ca7a7359cdcfbc448a91cbad838aa24d025d37b4889ed0f5bc6672d9dd8fcc97b5af2dbdf6f0aa1d4fca118cb11fdf2e93038d9cd233e6bdef692f4369ef4876e5c04cd17ea76d8878fee01a8c34fd25b9494775d40d81ae3acd0202d5a567a286c90050917d9b179e5d6b39ee1fefed4b2680da5f76a1175ccbc58d92a5eddf0502efec39eb6f78a2c72b6d0df8b953e2b806091b454f18fd23622c98c5e765175949df2dd06f2f16d1a954fc589ab63a756d4807824d908e2ece911cd6dbfb6608d6863e665d4580db4b53b1cd44bff567a33a6b123dd5bffd2a7e41a70c7d355c349be8
#TRUST-RSA-SHA256 3b8c269e526668c931f52749d7124647c2d507a636dc096e8d472b0d068ef7bcfd0d0f7b513aad32f59d8a54314c535316cf8073b972a58945b1e793bc7f4b07299e090023cac339ffb564b8225959ca485937cbcda1263127e8e56cdca581f3e5760f0afe29e20d264000d5b89a287911f133df665cc068eae28777741753ab84fab4dd5ce918e7b47aec76d43000d62e79145b06523dff8a34229ea42a79d4ac890cad1f0ab0e5959e7b572f017e95ee4110c6a173148af997e267445d3816acb9ae1fd3a71acd0acc3c44416584e4394c332a3463aa373b5991a576016d006572482949f3894b445b9dd1f4a86a0daf75d300b36e4ae271a89b4895c578aaef29448f730d6942e6ee31bc7da73870cfb539c760d58d72cced23e79a5495943bbc8dcad2693a70863030f717ba4a050079d6cf6231102c8965b3219e8d33961fe1fb147987371e5d47515f89504ed5232fccbd42678d5d4b3ee753d1fa3f974dfe9dc088e80d97ac15323da211e52544f94417946d141d08cb6930808c33a7fdaf203c0f6646eb7bf2d6d84e714df43f675b3f483b50b87a817454a2cc14fdc959d1ae68bd3bdef8c965806c5377899a012b649469b940aae137118a8cd3b43050b8a776c83313f5a0dd210af2b6e501b13e020eef166d3c556c625b1a931d96ca8b8344954315915c035c8f0e50dd1641a54ee73f72ec4224746cf211f660
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155025);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34794");
  script_xref(name:"IAVA", value:"2021-A-0526-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv49739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw31710");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw51436");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-snmpaccess-M6yOweq3");

  script_name(english:"Cisco Firepower Threat Defense Software SNMP Access Control (cisco-sa-asaftd-snmpaccess-M6yOweq3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability.

  - A vulnerability in the Simple Network Management Protocol version 3 (SNMPv3) access control functionality
    of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software
    could allow an unauthenticated, remote attacker to query SNMP data. This vulnerability is due to
    ineffective access control. An attacker could exploit this vulnerability by sending an SNMPv3 query to an
    affected device from a host that is not permitted by the SNMPv3 access control list. A successful exploit
    could allow the attacker to send an SNMP query to an affected device and retrieve information from the
    device. The attacker would need valid credentials to perform the SNMP query. (CVE-2021-34794)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-snmpaccess-M6yOweq3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?973fba99");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv49739");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw31710");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw51436");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv49739, CSCvw31710, CSCvw51436");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34794");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.4.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv49739, CSCvw31710, CSCvw51436'
);

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");
var workarounds = make_list();

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

  reporting['extra'] = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = WORKAROUND_CONFIG['snmp3'];
  reporting['cmds'] = make_list('show running-config');
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
