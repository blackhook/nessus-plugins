#TRUSTED 80cce4dd2e0d0a476845df4741e06bc0d18f205d17fa278a4ab388cfd47bb03e5818050b2428436c2ea5f1e601bf273954211734d9870712be3c5c500676fcdace017e8e57a68e5087c421a43a4cf6a79c795c9f0f33ad93597d6eabb57853c5d20613f043ba5d6160546c72e97d45358f2393b8c77c58ea7e511014b6af44e56b6d779dede5490e5903d1f84d4f179704bfe0b12f65a10b6f0249dfda040f421ef7632e3a7552c7cd5ba6afb4332deb433c4b1b2ca6d5ab593d43cd7814e72451ed935ea36962a2473baac934d49657cacbbff3122ef4e3ade19b79a1582146742ce213f5b737a19bbc7c35bdba04c5e09237a4556959ebde6987b037af43565a171e3169e8f0f1a8ca47021ab31b6aba9d55f340bac40969d5f3a8e33ccacff2588fd8d08161ce4651969224fb275b8f8559710a8246b89ddb005225baa26f8d4ef5d5e6c032290a8eed908dc6acc3869aa0003db2053ac6ea00eff726d34469807bc30e56a7e4e5301a1212ccda01828cd872a37c131b3bfad26f9d0b377f42ea52e28ad2bc22ce9045596045c89c7def2bba6a9842febd422a4870fbc68fe3877dc461e4a18ae907c072a300a9ddcf5697585cc0bf76344101e9872de80a251f81959ebad5b96b44dbb6b7e2a5c1ae0f691c89913523770ff69d648a7fe36226c62e1ac72649024159efc449bc8ea858850fe94a50c6b40872aa236c94bc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137655);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_cve_id("CVE-2020-3228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd71220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp96954");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt30182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sxp-68TEVzR");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"Cisco IOS, IOS XE, and NX-OS Software Security Group Tag Exchange Protocol Denial of Service Vulnerability (cisco-sa-sxp-68TEVzR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Security Group Tag Exchange Protocol (SXP) in Cisco IOS Software,
Cisco IOS XE Software, and Cisco NX-OS Software due to crafted SXP packets being mishandled. An unauthenticated, remote
attacker can exploit this issue, by sending specifically crafted SXP packets to the affected device, to cause the device
to reload, resulting in a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sxp-68TEVzR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc568213");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd71220");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp96954");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt30182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvd71220, CSCvp96954, CSCvt30182");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2S',
  '3.9.2E',
  '3.9.1S',
  '3.9.1E',
  '3.9.0aS',
  '3.9.0S',
  '3.9.0E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.2aSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.0aS',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.11.0E',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.3E',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1S',
  '3.10.1E',
  '3.10.10S',
  '3.10.0cE',
  '3.10.0S',
  '3.10.0E',
  '16.9.3s',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1c',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1',
  '16.6.6',
  '16.6.5b',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['cts_sxp'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd71220, CSCvp96954, CSCvt30182'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
