#TRUSTED 13c8ea602a75dc1bf270110277711d9b480aae4f9d8b4c01febf79a4016faae82bae48536083a9a068596a5271dbf675b6ca02b05d3844eb8913ce8c4767084950032d347c9f68c9f072284f812fd7a65cb37eae4766ef634e536b0cc5c82386870a49701b5c2c01912c6e44d7c2a58fea3fddc78fb29af343f9f6622c8974b87b1927f98dddd91b2b3cf88503231efaca4d4dc658b9ab8119c4c8b529f994143878d52410b5f375035fe30076a186bf835d820d217a6810ca58ca241874848d06662fdc44e1caeadd60faa1a02f967170ec89b3ce2cf722166d4eea75de7a494ac709a64d1359c6134d245f6f2b6ed16cc8c1a497b07341becb29f93afecd42811ca3aec3b98df16b9d1a9e35caf467729f98e5bbde0a067bf1e019b381bf8d84b8471a1d7b4a2cc3416915bac5a6cda34fd2ad29eb8b872b75f2d9c3647a9137fdbd19fe513e931e042579bbb575b7cd0a5fe606d2304839a0405a165684050b47ac5c0e5b93565cda561b15e213f681b9aac21bbb325379490b98ee8f7615602a325ce300ee7213c4242b8459bab44403e94816eab19a9eb62ae50c9d8d7d01381280352f428ec96ca08a8b9ea4ca57b0a5f6c6e9f6e3b18133e739ea439890d05933c9187501afd8167a76086c6bdfeb4db1f0a538beae29301d0f2a9fd8ba75d4a156fe59e294b56471b6312882b737395c14b5b59f8d685eddfee650dc
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141397);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr70940");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-dhcp-dos-JSCKX43h");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for cBR 8 Converged Broadband Routers DHCP DoS (cisco-sa-iosxe-dhcp-dos-JSCKX43h)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a DoS vulnerability in the DHCP message handler of Cisco
IOS XE Software for Cisco cBR-8 Converged Broadband Routers due to insufficient error handling when DHCP version 4
(DHCPv4) messages are parsed. An unauthenticated, remote attacker could exploit this vulnerability by sending a
malicious DHCPv4 message to or through a WAN interface of an affected device and cause the supervisor to crash and
could result in a denial of service (DoS) condition. 

This vulnerability only affects Cisco cBR-8 Converged Broadband Routers that are running a vulnerable release of Cisco
IOS XE Software and have a WAN interface connected. 

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-dhcp-dos-JSCKX43h
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f0db92c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr70940");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr70940");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(388);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1c',
  '16.10.1d',
  '16.10.1f',
  '16.10.1g',
  '16.12.1',
  '16.12.1w',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.4.1',
  '16.5.1',
  '16.6.1',
  '16.6.2',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.9.1',
  '16.9.1a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.3S',
  '3.16.0S',
  '3.16.10S',
  '3.16.1S',
  '3.16.2S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr70940',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
