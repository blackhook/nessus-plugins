#TRUSTED 73648cd677a9025849e056cae968dcc0ab7d02b3147a51d01e20b5bbc2542bb4725df7ff151fd25e155327b500b97e3698f8d2899edadd22b1293233bb1c8973222ce6902d9ddde6a8505ce4d453fd2f2121306aa025e764dac8ffc8bb2bdd8a6a294255ef7e82f7d379d7ef0e8f99fa62e8fe9ea51fc04edbea5ab4343c7c3789a605b6b03ddf79613a48f9afc03f706e28a899935e1a5ef9b6a0d544ae9ecafd4befdc8fd15f44075f2147a49c875529ddc73d4272e83563fad41eaab1e091821c2eff5c1124ee15475ef1dfb37542e1b27d778c3c6a04be1ecf7489039d49688afadc58fe1aad4eabb293ea350cbabcb11a24d95b05fe83de9cf10e7b908d08d2cc70792a67ee4d865061b02ebccd3a852a6d84e38fab31791a7dcc46caf8f5032ab1308c8eb2d1a208c583b9d4c3a2d2f334ac74c4ac050dcb1d060d2b62a8b3343042d9d0bddafbf5524deda19028761da6969acbf5011cd490b37b53864924e02d160136a14819b7cc2490f51e7b53152d5b6e5a84349d6157ec7695668790435620eb3ee2a300ca181758cd835db783c34e8956159d2775ea92fd64d4f22bdfd6a63c90dd024680b2c23a0179c969a7d67691442a3d47b7806306b0239a092c7c9975911d93eb18f8cc984f3886eb1effcd022b257d1c4f647bef322e3adef5418d451a3da2cacade91f3df2fe8d323422b8e0e4b2e3a4abce9246b00
#TRUST-RSA-SHA256 7d361fac0bf363d2bf0f400b461a9348202fa6972dabe7d95bf343fcce095098a627af55fdaca6aa4e48c7b7b0741abb732309adbcc70468a3be167481fd9120f45bc39f6834e587983078f5a1481b1b528dd695c9218c8a8639d9f0db4a9cf09e1369e677be67a69ea904d46062eae501751f6081d2bb6b1cc86996441fc5b4ecfcb0c6f2cff411ea9a2085aad906bff4abb19496f7a15c844427febf4d9bac4be6519d98774e8634f5acfaab0a2bd7365196a4a05a6baca703b538183779064b07c1620f7a4fde723fb4a16a1c994844642254644db49fa4c8be741b7657ad61e4e3877480ec7680a9d51a31b3b5da24ec0d7d54be8776f6c0580dec235fac665f69ea3f6d20cf61ebffe89b98e9af9da673c7fad7c76596bbbde3e4895ab5ea49f2e1ccbe5efed369c1964c22964c1cd545b06d010cb36e635ad37c298a8c73c15669e1769d94443deb9ccb5fbeb6953f9a79d546e6d2bb489b7288b3878b77a512230993fe45c3df762f75cb02256affd7e13a8117ce4c49c09190882a66349a6f929eeec1175e8679498408f56b11fd32bfbd52d01ea46e13db4f51eec7eaa9fa794b70ec4d7af6fa55015e174df16850f76b8d4a20501837c46e679680c0fd734e92651e6f1ca965b0446a6f8fbebb519f83f170ea649505c9d4ae358fb2d0dcf0e775d7bfbfd9442c9b1c71fb3f6c59f651f2cf721f78825400e0ba91
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138894);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-3452");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt03598");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ro-path-KJuQhB86");
  script_xref(name:"IAVA", value:"2020-A-0338-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0060");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Read-Only Path Traversal (cisco-sa-asaftd-ro-path-KJuQhB86)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Adaptive Security Appliance (ASA) Software. An
unauthenticated, remote attacker can exploit this, by sending a crafted HTTP request containing directory traversal
character sequences to an affected device, in order to read sensitive files on the targeted system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f081787");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt03598");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3452");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.42'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.20'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.74'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.42'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3.12'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.10'},
  {'min_ver' : '9.14',  'fix_ver' : '9.14.1.10'},
];

workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt03598',
  'cmds'     , make_list('show running_config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);


