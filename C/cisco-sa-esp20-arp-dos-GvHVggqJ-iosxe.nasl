#TRUSTED 9b3eedb4de87142fdb923fda20a7d27c42bd9e2ca728662fb2b228b61a11dbe77e2db0674d97fbc97a8b040e9ca5a32109c7418282ad4867a7055c6a4563dff1138733ad9a506a00a889255cd1f16f822d31f3e07834c20c3514421b4fd7b402d786dd8d3343cdc33dc8d927ff44739e7bb9a9e5144c2a2b894e0c1572e6be4042e3ddc0bfb2eed288db61aacdc2e8091f344527b1738e8665ef8953b76f12691d9bda7c2ff4f11217090f2c522251b82d57690809909c129dec4fd81c819f788a9896b8ab4ed216532045dd4d3712cc50589e52a810ecb4f27e6d2a5e28e846258a39108519177395ced951ec65a26503e5819a61070eb1e8a8a8f1717042c755e7176f51ba7f1f460e2a1ed1507efbae5160a8e03d0a73890d4e1140583a411f1c7872939c774cef4de4310348d2b52e82256cb2be2a9b63c28c24cdba10240aefecd018679d1a4c17e23001bb0bcf991a9b4e9cc38dcbbfa943d3e7c0d8f71afef678fc2c42303ed3a2eb4c8c23677065a2e100a136e6c9f50374e08527697eef7691bfbe6e70031d73fcf8b1aaf8b14cdb125421b55bcbfc835249e423589a7756158c13fbe49e18bf7a5d295246faa4fc9a459ae796884933423fb283348fd6b1a4c9f255aaa3419591a5164bd3de00d36a205fd5ee33d5da69b5aeae2524d8c9799c77852952a0647d4555dbb8269c63eb66d33b21982eca4b0f8309e1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142366);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva53392");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu04413");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esp20-arp-dos-GvHVggqJ");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for ASR 1000 Series 20 Gbps Embedded Services Processor IP ARP DoS (cisco-sa-esp20-arp-dos-GvHVggqJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco IOS XE Software for Cisco ASR 1000 
Series Aggregation Services Routers with a 20-Gbps Embedded Services Processor (ESP) running on the remote 
device is affected by a denial of service vulnerability. An unauthenticated, adjacent attacker can exploit this 
by sending a malicious series of IP ARP messages to an affected device to exhaust system resources, which 
would eventually cause the affected device to reload.

Please see the included Cisco BIDs andCisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esp20-arp-dos-GvHVggqJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f0f71d2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCva53392, CSCvu04413");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ '^ASR10[0-9][0-9]')
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
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
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.11',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
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
  '16.9.5',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1LA',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v',
  '3.10.0S',
  '3.10.10S',
  '3.10.1S',
  '3.10.2S',
  '3.10.2aS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.10S',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.7S',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.10S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2bS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.6.5bE',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.2tS',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva53392, CSCvu04413',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list);