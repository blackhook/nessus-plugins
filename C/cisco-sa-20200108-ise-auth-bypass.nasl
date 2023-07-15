#TRUSTED 57ce3afd44712856550fd2f6ca48b5629893adf95c2adcf6ab30189dc9d2092588454c51e845f8fd9d2b6ac24c43beae1c656461929e8d5baf319b643127baa0d32568e49b48a6dd4124aa1af1ce371782773be05d2c13c8fad65410a587dde4f7ccdf1ad5561c261fd4ceb8af012a4f0d9555a161274d13c375c4da4fe6da5b21315f7ac9f885046d1f0bb8e6155250a50b80e37ce4d246b008acfe964711373823bc9c5946590907fa2be478a0b1237b5808882e3245e0855aeac314cd6c863c37ba8722899baf59b4075ca7b3e7041859e4046616a3d92e1ffa4e06ff861fe008df8b3ad31dbf7d80826aa47b61cec492949ce95cbc630f99af03d9994f3e3b8044913570ff534fb6ad838a500a766714528248da41f8a122364ece4714b9cbc4b7a59368af59fd36c10c82c693fbe810a9408074d94add3ca426f1a704ec69874248967d22cc4eeb6a05a7614792e8eb93b7857feea40509e94e6be103e43ad06ac56242205e6119a3ae576a416232f3771242e4c0257062671ec486d541f893f8cd6681f43eec6058ef06ae47fbcccd23948db4f63598f136a3d806b2eda6b524c3d6d0303d9edf810817ec15bdc634cdce12af0886e72435731e3c5678c57500ecfeef40caccc260d550c1411b9a6649771a09c8ebd967ff2008842774df5b7dd1123d6f0f6c02aaa2a9fa2a45b1896f8927f11b912b468e2ef41f65b6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133864);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-15255");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq67348");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200108-ise-auth-bypass");
  script_xref(name:"IAVA", value:"2019-A-0361-S");

  script_name(english:"Cisco Identity Services Engine Authorization Bypass (cisco-sa-20200108-ise-auth-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in the web-based
management component of Cisco Identity Services Engine due to
insufficient validation of user-supplied URL input. An authenticated,
remote attacker can exploit this, by submitting specially crafted URL
to an affected host, to bypass authentication and gain access to
sensitive information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200108-ise-auth-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c44d3d67");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq67348");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvq67348.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  { 'min_ver':'2.2.0', 'fix_ver':'2.2.0.470' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '16';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq67348',
  'fix'      , 'See advisory'
);

# uses required_patch parameters set by above version ranges
cisco::check_and_report(
  product_info:			product_info,
  reporting:			reporting,
  workarounds:			workarounds,
  workaround_params:	workaround_params,
  vuln_ranges:			vuln_ranges,
  required_patch:		required_patch
);
