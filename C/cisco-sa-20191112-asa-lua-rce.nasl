#TRUSTED 2691e6d5eac19cd40de20e792e5d92a8812341f1141ff59caef24d572cc440fa4f4f93ca82ce68397f1ced3a93f01ef635d490d306dff23d41ffc35764d237e55cd642da47c8ffc830148c8be7f9c91f25423512a41ddd16c64e52f61067c27f7d78d964b79030ad19f8d13ce952c6af173ee9ea8ca2943de92410d2967be6f2b6c6fb805f596639eb70d8bb3da6449b10aa2b12b2c9c3e88ea79df7f27ebe39cfd932f25f541738ad93b572efa378d7a3d9fdbcfebd189244e8c7bb2ce5c50205a61d6e547da009f7f1803fe6abad66b5bf0875f8fc5afae0341c44b81ba20df1ebb5fc1931d4554765e7c7f7fd98b89510b557bc9b0f2fcaaef7f132d1a34b4f23e2eee4759187f59afac1637a9c673e6afefc00b158aa6b21c984e16b9bd4f730288e886cc91df6e6612ff23b0e22571eb512922b4bed6f1d7752fa09c12a6198a337ceb1c627ced5d4a8d598708f83be07a25ef5718575aac1884099058d15519135e368c9b81076522d59f699f7707b2ec75cb5d499d361741a53ea58302d5283dcb641b9dabd9a52c02d7ebf2efc6bc8c91e1cb52d707561c46806057b6707e6411e32f684b25e4b63f169b2ea494cff117c37efb18778e81b6de436e74a07fc89cef6dcb6addb54ae8b5c6d87dd46713cfe5d1a65736e11143e03e4135573ac14b9dcce9d4d5ecd1bf162e64d2c1abe4f3c6fe311a3326046bbc0b78a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131228);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

  script_cve_id("CVE-2019-15992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr85295");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191112-asa-ftd-lua-rce");
  script_xref(name:"IAVA", value:"2019-A-0425-S");

  script_name(english:"Cisco Adaptive Security Appliance RCE (cisco-sa-20191112-asa-ftd-lua-rce)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in the Lua interpreter of Cisco Adaptive Security Appliance (ASA) software
due to insufficient restrictions on the allowed Lua function calls within the context of user-supplied Lua scripts. An
authenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands with root
privileges on the underlying Linux operating system of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191112-asa-ftd-lua-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e82478b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr85295");
  script_set_attribute(attribute:"solution", value:
"Cisco will release a fixed version in the future. Please refer to Cisco bug ID CSCvr85295.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15992");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.6.4.36'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.4.15'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.61'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.32'},
  {'min_ver' : '9.12',  'fix_ver' : '9.12.3'},
  {'min_ver' : '9.13',  'fix_ver' : '9.13.1.4'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr85295'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
