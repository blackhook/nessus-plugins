#TRUSTED 2f137219060594ddcc2fa90fe72f1f485e16fb5be787cf599944eaad9353fbd092272ccfe22a26d4f66f177ef41ed1ec6b4e8d7586dfcb318ca83f1924da65f8f6460dd06d78c09c6e07dfa3870a399b05f15c6ba2f5f1e1718647dd1336188797fa7346c54c10a355522de6d1aa58e6164a93d17461133d6b56d633e95c6b26997def6019d1ac6a4e61ad2fedcf5531dfb22acf2c5a8b303877f1b81b2435a9536a4e2b741bff5f01edb98f03f543fbca75616751202c9f4ad9fd50bf600ff5eb16728c4f3b26abcd78707ccb8947613d0f4bcb0588fbdb4a3a43f38e84bd4ed58740678447968db8008972dbfb604aa81e619fcffd4807d56c63d1036d65eaba5bfc73fe5344c0ae62ecb031d7a3a5133749be0ab239fb11229c81c0f97e4346e5145c2cf47cbc8744e1da2d7f53d575e512838c7194b39002063cdea66da9e95015661f7880caee586e1fd525478d415b2f19d8599985f221fea5a1b9f3224712d0ef6ccb474643b603b725c0cf72657e9ab5a1f783d28dde3c494bb31d15600a21778f2e1984925f3fc36862d7a101f4cef2cbfbf4d50b01e1d945417a419c35cc58d4760e6d3b13289c6c0c2528d094d50d425aaabd9959707c9b34f9ac094fcfba1394b9dd7f3f6a75195e93844d03c874248adbd8b6105253a02da3034ad7e0337b1136c0cc4d63e01bda94126382c444e4042b260e3ac8d1d502ba54
#TRUST-RSA-SHA256 ab96b5023d35abe609e5fe405604d584580f6f457ec525401e9e8e641126849922b7ecdec2ecee8fd5f16f81754bc48f60a66e4dac83155951eec4b1c51b4414d03239ff51a55d466b4025499bff698a562ecf30347d2163e131ed56b91b3b6929e3a693c788c7ff23f1a504217c217dc78490f51d840aada278bd5953ecb5d6583558b0e4c37d3270a2d3ffb0fb6b147066faf31b797b95a3e910b4388a68de0e3af182b3217d44a54c34d14300683c16b24b84406db9513be8deb832d0b155d428341cb2799c59bb01bd724abe4fde98d1e57acbc6f53e4948b9ef71c2e3e961130b42d4e09a634845a428b0140f6cbf36b71b21c8792990afa6c7faeac15e875689093980c5caf3cf2f7133e76450584dfefdc835ea1bcd2d944d80cc7ec2ff9975b2422615e2832608ba7c3ae658590ea3aea823212ece9ca1add674799bb843310912c92eac42128f4b817073f5963a88303d9d29e191219bf794f0e111832bbf421d92b6f0059a22a8474b2704b8f7772837a7d4eee1e29fb1b0ce839d058dd506e22cf3913a4159b3a78d2a3518be2c8eee3e2ad39df3b503d0d2c5bae427a396939553a2b1f3cd8061d1e3c8855fa8034126bd3982e3df39ae97e8eeb5fbeea4562820a51314fea0305df8cd8b4aca5d67d983d74539b021cd0457b3d8258f5ef6a725102edfa356e9f25ea0022ffa67601bcc180735031f6f865d05
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141831);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3304");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs10748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt70322");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-webdos-fBzM5Ynw");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services DoS (cisco-sa-asaftd-webdos-fBzM5Ynw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a denial of service
(DoS) vulnerability in the web interface due to a lack of proper input validation of HTTP requests. An unauthenticated,
remote attacker can exploit this, by sending a crafted HTTP request, in order to cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webdos-fBzM5Ynw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fb5929e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs10748");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt70322");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs10748, CSCvt70322");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '9.6.4.45'},
  {'min_ver' : '9.7',  'fix_ver': '9.8.4.22'},
  {'min_ver' : '9.9',  'fix_ver': '9.9.2.80'},
  {'min_ver' : '9.10',  'fix_ver': '9.10.1.44'},
  {'min_ver' : '9.12',  'fix_ver': '9.12.3.12'},
  {'min_ver' : '9.13',  'fix_ver': '9.13.1.12'},
  {'min_ver' : '9.14',  'fix_ver': '9.14.1.10'}
];

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config'], CISCO_WORKAROUNDS['rest_api']);
pat_list = make_list("^\s*http server enable", "^\s*http [0-9.]+ [0-9.]+");
workaround_params = {'pat':pat_list, 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs10748, CSCvt70322',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  require_all_workarounds:FALSE
);
