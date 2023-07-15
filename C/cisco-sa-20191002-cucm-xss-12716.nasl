#TRUSTED 59160ec2c4d9e19506635e7a7eec498840111d9435d23e0a49e1e84f00830267eb8ba7b6b6c00fb9f1e7de9db8f1454b106319d1d22a704e9d275d2a0f06e3ae47a93cccedc21f64a4fa0e5e04d81c75cfa860964034e0387bc5989c5e8655940980fa4c1f26243444cc5c1b6d16ad83e5dc5c89d61f4a0afe5b5a17620524ce1cfee6f60ab529d27f4efb60a5f67ac7fcf609e76bcd12155d70848fd68ce681010aca7d4ebcc6ea139403d378251eefc50cf162fff8dd3292b763df64508a08d412b4d731ee4152d92d83b496159c61451e468aff3aa71e9d224421ca0cc05f362b83456d71b2c58e9e91914a791300958e0623dfa5466ee91e4f098a97c1396e41b4189e31b3a5a1578aa133e66a00c4813462c39dd9de1f69a7c79b81f885f9f65e68ec093820418032263a78c6ac0577b2018ae3a7b583db4ccbd5f80c21f5749ab8f12b6fec3436e3333e432aa27209e7c4baa41d5b839bcd77cf55a0476debfc1b71dbd3f147eb68ccb4adb6bee56e3b2681f24ce66f2552757a3b05021c0c6d74aa9bcdcf029c986ad3b14aea1bb947455638c2f170909a959b04a3e7921120a8949f58283628f8276eb5d40205f289d372d15ce22e407e1e1b9e44f2990f37e8242790de1c9e311b248460a520ce63df8f20626f92f3a0b6c73761bfcb1258b5504890366b2124dbfac981a077d9ee7bbc26e37a19f3249856345594
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129810);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12716");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42317");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cucm-xss-12716");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Scripting (XSS) Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by a cross-site scripting 
(XSS) vulnerability due to improper validation of user-supplied input before returning it to users. An unauthenticated,
remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script 
code in a user's browser session. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cucm-xss-12716
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84742ed9");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42317
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3d6c168");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID 
  CSCvo42317");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12716");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '10.5.2.21900.13'},
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.16900.16'},
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.23900.9'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.146'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo42317',
  'xss'      , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
