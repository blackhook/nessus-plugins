#TRUSTED 12663df9d4990f6cb21a86c8208935f7e8d7c5d2f64df47ffae635c498f7dd9ebee92dc848c145b12a85977d3cdbc55e024b526040fe0bcc93fd869769aa3ba0b21cf9bc4321f9619ccc81b76cd71bcbdd70f6c6da488ec564ac681e7ddb1d17df4460363447eee66dc26854432508bb0e799f84f47c8458ae146696deb5952c1f77b6dd636c9da0fc5551f999dbb1d6bacf948c3f06fdc0977e371d29d2666b955080042185246793a0b6a27f42d21026276762df0c98ff4628918a99995edf5d907821d61c5d7099d1ef78fc78db0c8f1dc620cb46d8ed4442481fd3be9957f80ebe8cbc8d722ad1cc30bb2f42ceae60d438707f19b69dab88d4a7d43b305425be6be51cb9b1d5d9e8b95ce96610ecde9f75f6fbaad4fae54f8ff5893c613252153821169f25c45f14ce8faada937cdbe2413754880f907a0be9ad555b48bfb513e85228861c188db69c1f597741339a8f6ad4752efac1abcb2ebb86d7e08da25d091f9c7db9ca54b26b58ecf192e2ab0087704ff233ed45682aa6dcb8620ff077125a840f27e915b61130565df8db76f635cbb8e754d883cac5ac4a7a6280f909ed36c878a548a9e308cb1d2f04b2d8785537bb3a01e47cc03a2f8524c46bb83aca88588bc341f78f47da03bfbe1d384a9356b30a006485089789a5541d7605f0b085b1d67d0ee1a00c834ba6e5ff8f45634df386786aedd62dee19ece065
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142494);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/09");

  script_cve_id("CVE-2020-26074");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21757");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-escalation-Jhqs5Skf");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Privilege Escalation (cisco-sa-vmanage-escalation-Jhqs5Skf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a privilege escalation vulnerability due to
improper validation of path input to the system file transfer functions. An authenticated, local attacker can exploit
this to overwrite arbitrary files, allowing the attacker to modify the system in such a way that could allow the
attacker to gain escalated privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-escalation-Jhqs5Skf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d229604a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21757");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21757");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26074");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(250);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.2' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv21757',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
