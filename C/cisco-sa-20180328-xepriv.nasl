#TRUSTED 83b44054498b764ea8f79c228e40c6f56ce21b0238f0812c8269f170f7139ea872fc4a73814957bf9121bedfe120d15f1de813e8ab941fef44fc67cee715f790e9193c6ea668c19dc3b7aa6d5c8d8d1022f6fd7a52337ebedd4379923d1ab3c87305b1fe16e5b359cc85285a5c3e316a375845bd153fefaf1e4613cd1bcaef4d3d2c19fd8794a2643a451525e1617b5189a263b3188d548eff7bb3ff66553595e75c82e2864dc434b6fb59f0d22f3cf49acbb138314b962f04fea555e6ab5a422602eb437a0c7bbc3716209ee48d4172bdd9a142578105558aaf6451dbf778bfd2f5ea2d12e030d292153236ce04aaa8f308a7d7d2006015e43197c3695192e63bdfff9d9903d412aa595d26e29242290c447fe489ae33e94ad0ac7848952d008e66830a708f3bcd1a0153b1908beb2d2fbada69594f38588775bc41e48fccaf604b82abfa199533ae6a9128bba6da0e3382a45d62b680fcd1efd4fcc84c5b959284f11ac5381f0780030989f554c6bb4801fccf398829a99baccbe4b3b41c62cdd504fb36f9605a3deef924b53162cd686e1bd2c7eee80554df6ad37ecd74ac323d1cd5640a376f631dbde6f1de45407797bdffce64bc575068786e957a0e4d42ea27ed9b418862c27d17439478159e65861d2868b641a75c3f5d6a7f9d4f8220fafa412540d574f213dec8feab0dd3ab3081042935a46f9a4355a77b4c5b4a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131126);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0152");
  script_bugtraq_id(103558);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf71769");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-xepriv");

  script_name(english:"Cisco IOS XE Software Web UI Remote Access Privilege Escalation (cisco-sa-20180328-xepriv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the web-based user interface (web UI). This vulnerability exists because the affected software does not reset the 
privilege level for each web UI session. An authenticated, remote attacker can exploit this by remotely accessing a VTY
line to the device in order to attain the privileges of the user previously logged into the web UI.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-xepriv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bf09003");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf71769");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvf71769.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '3.18.3bSP',
  '16.6.1',
  '16.9.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'exec_aaa_configured' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvf71769',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions,
  workarounds:workarounds,
  workaround_params:workaround_params
);
