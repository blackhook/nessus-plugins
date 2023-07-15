#TRUSTED a9a2ae9bda07ac156d4bf8910fe4aa7b65e8c2b890dbbb2cd3a3b9e2995bdef4167130257221b3c312aedad20281cf75846bc3f3f65dbe427f7721e78de6f9067324e2307b8d6bcd7b915619ad3c1280de24c64795260ca1b7d7f49de4a813c488c0ebc4f34d23f9389e2507f19e6c5dcd587d25dbbe0233297a50bb7e219fb2504fe5cda2b863decdc3609f9f90e36ec818a81ca6e2b9a147573d8db935a240f30f3f12269971dab553071e06915d9dda214dd6774e1cdde457835e56fcf4bc3e430a6969eb2bd3c978642544b5a79901a5ee97d4ffd09a07af426c8d5d3df747a4a6414650a022e4fd751082fa1ee74b01154f23ac35c12133f5d97925afd1fbaf5d4e45245969060faa5ae518394ac4acfe93767705ca6f2d41ad722619136f20092fa2c075d6474754f5a2d1d8548d3d9df2702e7dca08de1d3c5804a1aff24c429cbd73d0122cc6daedf05f97efdbc5b27d28b34277925e361c2dee1b47db59e95cccf849189641d3ba2114c80670a216f44bbe5d704b1d5ca1aecf050d4e0b352a9706b92fee568fee2b54d7cc03c16b3430673566502d5cc55274aa7e3e361acc463a0e925d40c327acfd9873f53bfb116c3fd755ba10c7b059b372ec0fe61d9295ffa912ffdb7dc1791289ebd6ed9a71857e2e103ddfcc0babfca73a7c3138211b2f9164a70ca53894f47e38ba9795298cf27896e801893d4244f78a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141832);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3455");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt31171");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-sbbp-XTuPkYTn");
  script_xref(name:"IAVA", value:"2020-A-0487");

  script_name(english:"Cisco FXOS Software for Firepower 4100/9300 Series Appliances Secure Boot Bypass (cisco-sa-fxos-sbbp-XTuPkYTn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Extensible Operating System (FXOS) is affected by a secure
boot bypass vulnerability. The vulnerability is due to insufficient protections of the secure boot process. A local
attacker can exploit this vulnerability by injecting code into a specific file that is then referenced during the
device boot process. A successful exploit can allow the attacker to break the chain of trust and inject code into
the boot process of the device which would be executed at each boot and maintain persistence across reboots.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-sbbp-XTuPkYTn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61b92d08");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt31171");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt31171.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.4.1.268'},
  {'min_ver' : '2.6',  'fix_ver': '2.6.1.214'},
  {'min_ver' : '2.7',  'fix_ver': '2.7.1.131'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt31171',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
