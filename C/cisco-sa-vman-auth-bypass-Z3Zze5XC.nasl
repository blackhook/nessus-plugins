#TRUSTED 4b6940fb7ee76619650e2b2a2205fac4fda0ca93b73233f92b929e40bb26ca635de773271999a5dc16e206bd8f0e024bcd8906012b2106900b5ca81a67114a576aaef72c2950116e29bf90eef5c2a7c656ec5ac516daca2e4c61bf4a4fba649aae1cab7efa5c7a157f2f16b582f4fc501d985c00d17e2a89cab96180ea34b895ed11e74e241ede1b14eac893c5df94334dd4231571a316e1b21dfbcfdd474b217e69a7b88b9a2a8885f6041ace616624e45e5bd024febf5adcf674f34f12616427745d076cb0f7b3ef09c3eb82a97460b984cd0733fed384806670c7aaffc7404f00bc5317067b3d1f071417a26a2bce4bbd005ed0a7f08f89fbb4bcbd183346695dafdc0876d2624841296a8c230bbf6b63361c590175a625eff1d6b8dc9d1d61b336f11f0e526c72018c0f19fed1e959e5a001771accf616ec051dee2ae3692e6192e986d385d560d1228d9c65efd25235c9b830710182baa0a7c97b68f3a14a3f404379a395cd0eaf56c2f59880933b9e45e272e7cbc15aefe5db1a256a4e9db0ea60be0ae7e8d7bc4dd1bf05d199cdd1fbfdf760d41af691bafd2de598be42c2d60d0a07fd8df05b67ec161028da011e276a36234fcffc0e212c07f048fb49908a1cd476da672677fed68b87df89131b2cb7a01b6d79b1ecd715f1a6bb987977c27bcf2c63c375b8114e7df544c015c4f0c107633a7768ac53c5820c6acd
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148978);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1482");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw93076");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-auth-bypass-Z3Zze5XC");
  script_xref(name:"IAVA", value:"2021-A-0188-S");

  script_name(english:"Cisco SD-WAN vManage Authorization Bypass (cisco-sa-vman-auth-bypass-Z3Zze5XC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by an unspecified vulnerability
in the web-based management interface. An unauthenticated, remote attacker can exploit this by sending carefully crafted HTTP 
requests to the affected system. A successful exploit could allow the attacker to bypass authorization checking and 
gain access to sensitive information on the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-auth-bypass-Z3Zze5XC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c8dd507");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw93076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw93076");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1482");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.5.1' }
];

 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw93076',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
