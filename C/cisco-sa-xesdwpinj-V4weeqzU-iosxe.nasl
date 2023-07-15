#TRUSTED 5b3f3d7a47dc904d6508aa3df1ca135752283378a388808dcc0f178cf977484cd10e81262a971141c739b1c865cb3a3ba727957976674f3bdb8bb70e90bc26d45d16f1ac14bb9f3b3385cab94936290d660e45683ada8bed90c243d85aa2ab3220420a355311e28357c7e71e63994c4bac2ae4ce5384482241d77eed83e2810396f5886845e25b7ea7a75122de141e71de2e8bbbe32acde0b795546f69fab86ff74ca1590c976f4f3f4cf489117e8ec5e20c158796fe28e970092cd02bdc31dcd6701b8a95dd39f387d9ab3929dbf3ae013dc77a7449e8b028ab4baa41581f72612dfcc550521a05c7078d17902ed4b824c85b232c0b2283457f2455274a30ec7837dc33b7f6b1013ccb725d10dc470f062ea56a448be3f85751ca40e857326147f8dced312e8e55f8485c5231508ace8e398e0539e33b3ee26d76a978b7015ce321974f4dd3bbd46ea090ce3963709d3e99cf756f09bc0cf2ed26e9b15fca4ce4e4e9f2ed7dd9461f63b099ce74010258c1e44a841fd1bf049687965ecf28078469247b6d1d6f4b562ca1c8fbf115cdc2d9857101853d7e05ad93aaabc9d2f03b2df0107e12c23f7de583645dd4943b13e90a32684410a8545f8bd2a5a512a9c6fb945d837be086c127439932162e6e8b3656034c9ba7b3634d43c054f9c7ada8718bb75daf7f0d5a69f19d08efc66c272c64909513cc11b652e60e9734d83b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148094);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id("CVE-2021-1383", "CVE-2021-1454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk59304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64834");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xesdwpinj-V4weeqzU");

  script_name(english:"Cisco IOS XE Software SD WAN Parameter Injection (cisco-sa-xesdwpinj-V4weeqzU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xesdwpinj-V4weeqzU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0f0c4f8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk59304");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64834");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvk59304, CSCvw64834");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 88);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1',
  '16.9.1',
  '16.9.2',
  '16.9.2',
  '16.9.3',
  '16.9.3',
  '16.9.4',
  '16.9.4',
  '16.10.1',
  '16.10.1',
  '16.10.1a',
  '16.10.1a',
  '16.10.1b',
  '16.10.1b',
  '16.10.1c',
  '16.10.1c',
  '16.10.1d',
  '16.10.1d',
  '16.10.1e',
  '16.10.1e',
  '16.10.1f',
  '16.10.1f',
  '16.10.1g',
  '16.10.1g',
  '16.10.1s',
  '16.10.1s',
  '16.10.2',
  '16.10.2',
  '16.10.3',
  '16.10.3',
  '16.11.1',
  '16.11.1',
  '16.11.1a',
  '16.11.1a',
  '16.11.1b',
  '16.11.1b',
  '16.11.1c',
  '16.11.1c',
  '16.11.1s',
  '16.11.1s',
  '16.11.2',
  '16.11.2',
  '16.12.1',
  '16.12.1',
  '16.12.1a',
  '16.12.1a',
  '16.12.1c',
  '16.12.1c',
  '16.12.1s',
  '16.12.1s',
  '16.12.1t',
  '16.12.1t',
  '16.12.1w',
  '16.12.1w',
  '16.12.1x',
  '16.12.1x',
  '16.12.1y',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1z1',
  '16.12.1za',
  '16.12.1za',
  '16.12.2',
  '16.12.2',
  '16.12.2a',
  '16.12.2a',
  '16.12.2s',
  '16.12.2s',
  '16.12.2t',
  '16.12.2t',
  '16.12.3',
  '16.12.3',
  '16.12.3a',
  '16.12.3a',
  '16.12.3s',
  '16.12.3s',
  '16.12.4',
  '16.12.4',
  '16.12.4a',
  '16.12.4a',
  '16.12.5',
  '16.12.5',
  '16.12.5b',
  '16.12.5b',
  '17.1.1',
  '17.1.1',
  '17.1.1a',
  '17.1.1a',
  '17.1.1s',
  '17.1.1s',
  '17.1.1t',
  '17.1.1t',
  '17.1.2',
  '17.1.2',
  '17.1.3',
  '17.1.3',
  '17.2.1',
  '17.2.1',
  '17.2.1a',
  '17.2.1a',
  '17.2.1r',
  '17.2.1r',
  '17.2.1v',
  '17.2.1v',
  '17.2.2',
  '17.2.2',
  '17.3.1',
  '17.3.1',
  '17.3.1a',
  '17.3.1a',
  '17.3.1w',
  '17.3.1w',
  '17.3.1x',
  '17.3.1x',
  '17.3.2',
  '17.3.2',
  '17.3.2a',
  '17.3.2a',
  '17.4.1',
  '17.4.1',
  '17.4.1a',
  '17.4.1a'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvk59304, CSCvw64834',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
