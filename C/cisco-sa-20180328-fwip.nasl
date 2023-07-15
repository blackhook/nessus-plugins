#TRUSTED 4b1e4f249166d3a8de67d5aad3326846084fd3c6b3800d8c98422232ecf749ea14b3afdd37c5127fb9c525ec429ddece005794e6edfa753ceb90ad3a00602e2e785fe02b9c3558a032835d743a6688bc4eec493768cdf73b58edb8b031ce4d456c31a29bf026bb68e3652e3645fd86936907fa16b6eeb7de99344d62715b6342a8f94951548663f87986bdd0a4910395796f767f0cb390ba443bd221255414d7211d7c69c9c056d1e777dda7af9dac58c68e85177905fa9ca630723da005b4b75133db2446df7a534f52ad7e4197fd6432d66eda1a601be69a3db51abaad0f33828baa765616a8d21c770e43111bf70b8b4517bc1c3e9049db9697db7214a9f3cbed0622c09b28c780459355eb0ed20489f0503653a02f97fc0ff8b75606dd4c0bbdf924e64b7aad8302307629cdd2c6b376f08f9ecba8697df5620b68893f6bcc5b582fe3427162cae5dc89ee58a573eb9a3afb3944075b6a63fcaef2e08b69a711dafbd3d935f9a1db43425d360efc0672b6851f6261abf9302cf58c9d8bc629dd7577405919a18bdf82f54f881a8d4d31f727f827c172f09f72efd76fadf76b3857bb5f46e62622a692941ef279ec67f563e0de27331a2999ae0e531b2d582b7207b3b49006c665df05a99c246039af0986f571017c498a18fecad732c44e022ab37cb1f6ce1a1e77fffa308907e371231c7a3f6551294a6ceb25e2f2eb9d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131130);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0157");
  script_bugtraq_id(103561);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf60296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-fwip");

  script_name(english:"Cisco IOS XE Software Zone-Based Firewall IP Fragmentation DoS (cisco-sa-20180328-fwip)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Zone-Based
Firewall due to the way fragmented packets in the firewall code. An unauthenticated, remote attacker can exploit this
by sending fragmented IP Version 4 or IP Version 6 packets through an affected device, causing the device to crash.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-fwip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcf72e32");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf60296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf60296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

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

version_list=make_list(
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.6.1',
  '16.9.3s'
);

workarounds = make_list(CISCO_WORKAROUNDS['iosxe_zone_security']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf60296',
  'cmds'     , make_list('show zone security')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
