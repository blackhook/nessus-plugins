#TRUSTED 1a850cca8386382d09633054ba33279e30e183bb30b18efa4ecf52a5373ad5410b82bb0ff7f41b661527fd63dd5a3474cad5eb9be252d9a333c9cb0192e0361e3c3a384f118682db847507d79a04fc000435c99dfef0d4615505781b27735b2a20f0a0adc1609ec8ebd8220ae2c9f19fa22446a8aa2524f165f8722905b621025b440a08a1b76b180933796d9294eb6fc8457a74286e48d2b2a68a2eff8fa0b2523722781209f8a2d9413f5acaa314f383e15e721dff29cbf26a4dea40685361a0bbaec9d1ff5f56fca9cdbaeffbac517a19b9c1a67fe712b5c5e9c864b5ced5baf736626083a93fdf1af9fe3987d567ddf32bae4c936b8e10ce8443b7a044a01ff93ad6a5d8353f7e09c8c5b7d27c6e9b16312e53b8c128cfa98873f04ff2e59408c35153367de299793886b4513dd9fb65456af71891216b963cc4f9b4df7f35e09831f2583f04341a1e603b174d7f9c31d73a1b8c88b3068826fe7882cd7da221e05a6e97991ad0c6c7312f573f76d0aa92a9dec2dc70147162a88bc25cfd681ec28762a222d2b0ab07e4ff0b09e62f518ddab450e541c562347f134b1299c723aa70eccb484c1fd0471fd94a6b5c149f4a93d22d2614b00aa5293febdd830f1cff6edbe82da8f641b99abe6654ec7249765c0143c7f88fc32add73a586721d52c1cc35d613cbb484ecfee41b89c0b2a36c5c11f162f99e4fb95e2d8849ed
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135294);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/13");

  script_cve_id("CVE-2019-12699");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14277");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14279");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm25813");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm25894");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42621");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo83496");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-fxos-cmd-inject");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco FTD Software Command Injection (cisco-sa-20191002-fxos-cmd-inject)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by multiple
vulnerabilities in the CLI due to insufficient input validation. An unauthenticated, local attacker can exploit this, by
including crafted arguments to specific commands, in order to execute arbitrary commands on the underlying OS with root
privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-fxos-cmd-inject
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ad074ec");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14277");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14279");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm25813");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm25894");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42621");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42651");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo83496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version in the referenced Cisco bug IDs.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

if(product_info['model'] !~ "^(10|21)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0',     'fix_ver': '6.2.3.14'},
  {'min_ver' : '6.3.0', 'fix_ver': '6.3.0.3'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm14277, CSCvm14279, CSCvm25813, CSCvm25894, CSCvo42621, CSCvo42651, CSCvo83496'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
