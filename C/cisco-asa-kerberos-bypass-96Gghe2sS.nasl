#TRUSTED b09e3be3eaa115071d9a6a5be7abe3b96e8c5dc00e60ffbc5e22981f6a10b41c1c02596f2b4674744f0f23c1522e7ad7787a04a060af4c41eafab528f23fb9a9d264de8dff06d27f65966cb5c6daa4319da6492c6dccf9d275d839b1f1e582b13ddaa241629fc75cf2f9dc754b510382f0c355a5b0eb3c6c9a2545ee67221d06f64d22110514d80583548d31d2f61158b6ae5deefebfd80496b848d88ef712f6fc4bf921c9100fcdced13190620cd58c4184af248934843344a524ad23f1bf47a4675559dc674a94b0c87ab59b052165a4318af1673d45de6a992320535a5bcd4b7f6d811ccd69c71d59fc3a1ddf1d9e3a21d02c0cd20430d0cfc70e82be8a1737a7a645e4b494936b8b6ba67a02f0a9be423c06d8c2bae4caaa01b38d96e921454ffa37458a1197a37df86fcda6f353b7a0972dafccaa8f830760fdf06f88e6c6b470f0b2e2d0dc73c5635a2465e79a127cc4006c25a32e90ef201218a44631ec0446606d77ececb53b9fbe4fe2c515928ab7d720e2450e87ef4cb62c82d3c24ce25eb105e521508878eb1f4d91a5573aba63c9c6ce89e8e6fd894aec7be436c3b7d004162999dfeccb583dd0a278eaadaa3f3458a21c655ef03ca3ecd2f4ddd1871ecd6c3f0de9abad51e1a120da5c0d50ed6a6ef29140db52d91b4a8dcbca8a183dddc4ddeaa52baf9bbac695d69bb2afe8372f554ea2a90cd77a424329d4
#TRUST-RSA-SHA256 6ec5b7ad7f57910fa8756537f2f393f9623a31f067431e1eacd9a25b4cf8ad0b486544dc052dcca56a5c68d5a62abd4a5a679b21234f74549d31a63387b610d80571e0d112e71dc4f457cde9c336318e008f023fe4b0d83276bc6a275738265b53098c4f940e0ffa2fdf34f8efbcfe2273badac561eee6bb2176ceb3d664c646405009033e38412b4a6890f1b98c4c287ea6694368061b128babf9b04a8681a464e760d4800d91d25eca0d47da72f7527286917d9b8983f6d2d875153d1a4d8f699dc6fff78cbc44f011f2b891cd5948910a8f3f8688b9aa5a391fc1932389e03be778b57fb4e7d9a1dabe456d85de1b5324561fb6c038aa46acb95af5fa92e888c9db011d66fb15809a8563c238314b8b4f7d369a82f11b9687b5c73a62304b128840872e652feaed22bce0e0274ba5bfab029a04a70cccb8ebc751fab258c4c21d48092ff455338b37ea199b564e8f3a5417d427701bae4c8ff7cd7703feaebe3ae209fc1ea443ddd0b26e2cab78aa299013aadeefc05c22dd0feec0075510b8e1afb5db7f11d34761ad1250ca933faaf40c94a3a1b420aa0a9f90b9dc70367c0f7a3d1c5371a0fd831353532d3ff8bc6dbb1aa1205ffe05ba483f9cfb4449e847d53b03943a010814f750b0da988ee16ea405e9ffd6e68f3f229da369ed46ee578143e8e867a70bcde36a7dba2336c842a6325e577f1556ac19d8289ba4ff
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137557);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3125");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq73534");
  script_xref(name:"CISCO-SA", value:"cisco-asa-kerberos-bypass-96Gghe2sS");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Adaptive Security Appliance Software Kerberos Authentication Bypass (cisco-asa-kerberos-bypass-96Gghe2sS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance (ASA) Software is affected by a vulnerability
in the Kerberos authentication feature due to insufficient identity verification of the Kerberos key distribution center
(KDC) when a successful authentication response is received. An unauthenticated, remote attacker can exploit this, by
spoofing the KDC server response to the ASA device, in order to bypass Kerberos authentication.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-asa-kerberos-bypass-96Gghe2sS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?441ad885");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73830");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq73534");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq73534");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance");
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

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0',  'fix_ver' : '9.8(4.15)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.66)'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10(1.37)'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12(3.2)'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13(1.7)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['kerberos_authentication_enabled']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq73534',
  'cmds'     , make_list('show running-config', 'show running-config all', 'show aaa kerberos keytab'),
  'fix'      , 'See vendor advisory to apply the relevant configuration'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
