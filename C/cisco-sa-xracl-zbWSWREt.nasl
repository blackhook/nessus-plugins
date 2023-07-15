#TRUSTED 64bf6065b6976abaec4c239f4c95fc4cdec609ce9bb2ab6b3ce668eb7aaeb773015882ea810cd496b86fe1fb813ac0299c173d0fe673cc837e0486a7f6bf43eeac725f25e27ce31a9cc145ea12d7c3378aeacca2a76770cd109bd86a6bb47b61182e17ded2136466e3e5083d53b63ec8a891340f4041f9b319de0bd95b4f2fa9e4edf8fecce46c85af0bfc57cc62137070429c2bed21b10edf6efcdeb355e685391478b38f0e1f0b66bb9fd705ad2fa090be8b4147fdbb072191b0ca426e3b44878598770613512cdebdfb90ac3cfe4131d93b5cda508755e6ab3e2744ee8bdcba4719556fb5944c2b88f69c1d3b96f7800c54fbfc58686fb05359bac8c5628e6e65c9f370be3b86d1ec81fa00baa3d41c83e20389254ad59f5586892e338153c423aada21988958ba3c5406b242ee09992579aeca8e7fad39d9b77819419319258f8030060f520164c02ee52eb535a7e08a2d24ef574d1afd722108c0ef6c1834bc780d96e8c259f7dbfc481d01bc9190e273ea2df6effe45e95547328ff091c72c872c6f8138a1265b120ec12df585fe5ec8cfa78156c6740d06b1e83598ac658127f5cf09f744e306c3ceeb85fa4655b44686521931d4c4e60a9fa2f5dca892d79ac4c24d4d23326577e04b35ce8ffd1c994795afd480b555882592297a9bf1fba0cabb19502b07d916e8ea1454172a9d19f3eb76ba402056b6a4bedb1348
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137851);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2020-3364");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt55079");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xracl-zbWSWREt");
  script_xref(name:"IAVA", value:"2020-A-0278-S");

  script_name(english:"Cisco IOS XR Software Standby Route Processor Gigabit Ethernet Management Interface Access Control List Bypass Vulnerability (cisco-sa-xracl-zbWSWREt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in Cisco IOS XR Software due to a logic error, which prevents the ACL
from working when applied against the standby route processor management interface. An unauthenticated, remote attacker
can exploit this by attempting to access the device through the standby route processor management interface.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xracl-zbWSWREt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbea3208");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt55079");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt55079");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3364");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

version_list=make_list(
  '6.7.1',
  '7.0.2',
  '7.0.11',
  '7.0.12',
  '7.1.1',
  '7.1.15'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt55079',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
