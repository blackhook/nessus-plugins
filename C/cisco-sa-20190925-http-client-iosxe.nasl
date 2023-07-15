#TRUSTED 7a68146fea27af6791fa0655d35be1bedc3d6802044a2874d9a3e21f1dd718c0cd8a2d3648472105c424bc4cb2d7886b752a0e0534bc4ba011c2299289d576bdf2b3d54d73d98684c74dfa0ddeae34d7c25c679af261e8356e85e6050edb2da7c914c9345e59c21fb3c4311bfc91f135d5f5cb61902a51511840ec637070d5bffe0285c25cf286f39c3a8a9c7ef6c103b377c0919d614721f9945006d38ccfe9d5421c7fa62f217e15010671e5b80e3eaaa814a070f27477957f8968df94667d163da6dc7e72fc4adb1e62eb2dc2663b50ac3066290d441812e1d3202cce96c5acf93c3f82f60da51850adb60c4e213424f98561187780cbfcaab059621676cba2a7c6a3b868d6df4155a74ae06cbd6e23d334776e98db383a56a4a955025668591ea5904d8c60e0e6ca24203751c54601f8494045f7c6dccb70f32a7e2d4062c888fce9c70b0af47b4c008f290ec802e8354b60a3a41c89269123cb5dd7e5006885cba98cab15dc2208bb589bbadc1a65be1d7fda4bb501b26002b06b72bec58961ea6263b924fdedf824f262d0750da29035dd47921d71ec1336e75ac6570dddb60be0faff506ed86d182f46d690b1a8041f3e38dd7e74b3b2a978a8d6d8ef484697c0026d3359dd6923ff4dfe1a81b88bf91acfcae88f605ab5673945d55c2d575cf4e34e33bb12519e01b64629ea76f1095cfa3a923687fe8b6f6e813411
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129779);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12665");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf36258");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-http-client");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software HTTP Client Information Disclosure Vulnerability (cisco-sa-20190925-http-client)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS XE Software is affected by a vulnerability in the HTTP client feature that
allows an unauthenticated, remote attacker to read and modify data that should normally be sent via an encrypted
channel. This vulnerability is due to TCP port information not being considered when matching new requests to existing,
persistent HTTP connections. An attacker can exploit this vulnerability by acting as a man-in-the-middle and then
reading and/or modifying data that should normally have been set through an encrypted channel.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-http-client
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e0771c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf36258");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf36258");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
'3.2.0SG',
'3.2.1SG',
'3.2.2SG',
'3.2.3SG',
'3.2.4SG',
'3.2.5SG',
'3.2.6SG',
'3.2.7SG',
'3.2.8SG',
'3.2.9SG',
'3.2.10SG',
'3.2.11SG',
'3.7.0S',
'3.7.1S',
'3.7.2S',
'3.7.3S',
'3.7.4S',
'3.7.5S',
'3.7.6S',
'3.7.7S',
'3.7.8S',
'3.7.4aS',
'3.7.2tS',
'3.7.0bS',
'3.7.1aS',
'3.3.0SG',
'3.3.2SG',
'3.3.1SG',
'3.8.0S',
'3.8.1S',
'3.8.2S',
'3.9.1S',
'3.9.0S',
'3.9.2S',
'3.9.1aS',
'3.9.0aS',
'3.2.0SE',
'3.2.1SE',
'3.2.2SE',
'3.2.3SE',
'3.3.0SE',
'3.3.1SE',
'3.3.2SE',
'3.3.3SE',
'3.3.4SE',
'3.3.5SE',
'3.3.0XO',
'3.3.1XO',
'3.3.2XO',
'3.4.0SG',
'3.4.2SG',
'3.4.1SG',
'3.4.3SG',
'3.4.4SG',
'3.4.5SG',
'3.4.6SG',
'3.4.7SG',
'3.4.8SG',
'3.5.0E',
'3.5.1E',
'3.5.2E',
'3.5.3E',
'3.10.0S',
'3.10.1S',
'3.10.2S',
'3.10.3S',
'3.10.4S',
'3.10.5S',
'3.10.6S',
'3.10.2aS',
'3.10.2tS',
'3.10.7S',
'3.10.8S',
'3.10.8aS',
'3.10.9S',
'3.10.10S',
'3.11.1S',
'3.11.2S',
'3.11.0S',
'3.11.3S',
'3.11.4S',
'3.12.0S',
'3.12.1S',
'3.12.2S',
'3.12.3S',
'3.12.0aS',
'3.12.4S',
'3.13.0S',
'3.13.1S',
'3.13.2S',
'3.13.3S',
'3.13.4S',
'3.13.5S',
'3.13.2aS',
'3.13.0aS',
'3.13.5aS',
'3.13.6S',
'3.13.7S',
'3.13.6aS',
'3.13.6bS',
'3.13.7aS',
'3.13.8S',
'3.13.9S',
'3.13.10S',
'3.6.0E',
'3.6.1E',
'3.6.0aE',
'3.6.0bE',
'3.6.2aE',
'3.6.2E',
'3.6.3E',
'3.6.4E',
'3.6.5E',
'3.6.6E',
'3.6.5aE',
'3.6.5bE',
'3.6.7E',
'3.6.8E',
'3.6.7aE',
'3.6.7bE',
'3.6.9E',
'3.6.9aE',
'3.14.0S',
'3.14.1S',
'3.14.2S',
'3.14.3S',
'3.14.4S',
'3.15.0S',
'3.15.1S',
'3.15.2S',
'3.15.1cS',
'3.15.3S',
'3.15.4S',
'3.3.0SQ',
'3.3.1SQ',
'3.4.0SQ',
'3.4.1SQ',
'3.7.0E',
'3.7.1E',
'3.7.2E',
'3.7.3E',
'3.7.4E',
'3.7.5E',
'3.5.0SQ',
'3.5.1SQ',
'3.5.2SQ',
'3.5.3SQ',
'3.5.4SQ',
'3.5.5SQ',
'3.5.6SQ',
'3.5.7SQ',
'3.5.8SQ',
'3.16.0S',
'3.16.1S',
'3.16.0aS',
'3.16.1aS',
'3.16.2S',
'3.16.2aS',
'3.16.0bS',
'3.16.0cS',
'3.16.3S',
'3.16.2bS',
'3.16.3aS',
'3.16.4S',
'3.16.4aS',
'3.16.4bS',
'3.16.4gS',
'3.16.5S',
'3.16.4cS',
'3.16.4dS',
'3.16.4eS',
'3.16.6S',
'3.16.5aS',
'3.16.5bS',
'3.16.7S',
'3.16.6bS',
'3.16.7aS',
'3.16.7bS',
'3.16.8S',
'3.16.9S',
'3.17.0S',
'3.17.1S',
'3.17.2S',
'3.17.1aS',
'3.17.3S',
'3.17.4S',
'16.1.1',
'16.1.2',
'16.1.3',
'3.2.0JA',
'16.2.1',
'16.2.2',
'3.8.0E',
'3.8.1E',
'3.8.2E',
'3.8.3E',
'3.8.4E',
'3.8.5E',
'3.8.5aE',
'3.8.6E',
'3.8.7E',
'16.3.1',
'16.3.2',
'16.3.3',
'16.3.1a',
'16.3.4',
'16.3.5',
'16.3.5b',
'16.3.6',
'16.3.7',
'16.4.1',
'16.4.2',
'16.4.3',
'16.5.1',
'16.5.1a',
'16.5.1b',
'16.5.2',
'16.5.3',
'3.18.0aS',
'3.18.0S',
'3.18.1S',
'3.18.2S',
'3.18.3S',
'3.18.4S',
'3.18.0SP',
'3.18.1SP',
'3.18.1aSP',
'3.18.1gSP',
'3.18.1bSP',
'3.18.1cSP',
'3.18.2SP',
'3.18.1hSP',
'3.18.2aSP',
'3.18.1iSP',
'3.18.3SP',
'3.18.4SP',
'3.18.3aSP',
'3.18.3bSP',
'3.18.5SP',
'3.18.6SP',
'3.9.0E',
'3.9.1E',
'3.9.2E',
'3.9.2bE',
'16.6.1',
'16.6.2',
'16.6.3',
'16.6.4',
'16.6.4s',
'16.7.1',
'16.7.1a',
'16.7.1b',
'16.7.2',
'16.9.3h',
'3.10.0E',
'3.10.1E',
'3.10.0cE',
'3.10.2E',
'3.10.1aE',
'3.10.1sE'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvf36258'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
