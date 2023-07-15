#TRUSTED 261b7bf582b836f564348c7cd3d147b9bfea10ce541d9c7db62ac62295366c95d399e2303654eeae36c9fe59e5586878aeb8046d9dd78997e71358e5633a05aef379511ef60dcf608caca11e168b21ea9deb96a12c1bbb9c079dd70e556a74f40d4753cb865aa342222e6569e09f4666889499d8a6b07132742de8471054b8c5b4b686d84b40039595dbdd824276f249bcf8f909f9a039cd1e94774033ca8bc3bf01fce9274fea89927145200a011c74dbbd254b70afda371eee644d266dfc4b5f8d75844e4b59961736c43ed363e7c19eefbe0c4688883db20457e47bd9b3f31e29a3090d46ce4147b9324c24ebcb77bbe4082ab1bcd7f4532774b610e61f81b92906fc0434de9dad2b055f706cf558c9a9aac066b59b59145089638483ae74f960e345c4bb4c1898cecc67dc0b4fe610ac1c61fb4a26d7b1f5ef46e6277b3742e05ba2e1137bd009ef8a8ff16e6df1ecf527513e0c53ade8fbfeecb0510c038f9dcc698333ebc367141fc9c4a69241d68860968332e43a6150d4c393bcd3f3a97dc83648aeac092f98800dd9cc5e77656635f90239d3210f584581f8b78480b901272af833b1c26ee6721eeb9a893d88cc891b0f4ffc7a3c82d692a5997c99fe8b315e7d856fce9b47d037ee6964c6a5debe8b22572d798eafac4c5c499f2946634e45e5e92e2c5716b1b395a3604ed7ac968bc6d5b8c16ffaa3847044176e
#TRUST-RSA-SHA256 4f84bfe84ca22835ad95556afb3e5d21b99e3c9c7d713a902c98b053283d0eafe45fe27aaf8d54ef38ef1223db7286e269cb19bf635a167754f37c77455d068b52c910b7ee3230f9e295a07a8106d75af2cc77582f08aa42ca322b8c7d2eb07437b541eb024718015cf8f9a90fb3d15fb0b6a082503a5a7cd55506a2e0aa810075ae6fe17156940d4b40f28f71ea229aa522d45507f2b0ca4fb52153a4fd9c34425d8db3da3421652e83975899240a335f58eaedc5cf09162a4c51da1e5b992d213ab58f008784411d9a0b38755bc5957a55e3de93926a581576a9e5a1406fc4f67df881c833b6da161c6518133fbc8eed7992cc0fd994243f22801e9e05d23d36f9cd1ee818364c152ba679e52c339113b257aff742cabefa106b5d8f92be3f3a97dc0aa10f904bf090e1f94b524d9d46f0060e7f94d3fee0d03ce79d7a8592cf9ad1ed171a54027e8ebaf379ea3015bbf5fa9a85727db03d43692afd8bd239c1d9ceddb16eb6f196d2655d91f33ae1d7c98f7080dbbe0d1e375b52761997e2ce14011ae9a7d0094390ad0d94252c5e37c2ae54ab12825c671e8216acd176fd3c0c7abe89e770a5b025380d6d0dffd851e56b48a261880b000009a4be7bbcb932209c87bd5a71b21c45f32a3597958d7a3b5a0aa5ea8f7092c38df9d408bd3493f4d1c556f792cd63dbb772983230f0026e42435a1f0b3f2f58a5bc68aed7f9
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166681);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-20822");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc62415");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-path-trav-Dz5dpzyM");
  script_xref(name:"IAVA", value:"2022-A-0462");

  script_name(english:"Cisco Identity Services Engine Unauthorized File Access (cisco-sa-ise-path-trav-Dz5dpzyM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a path traversal vulnerability.
Due to insufficient validation of user-supplied input, a remote, authenticated attacker can read or delete specific
files on the device that their configured administrative level should not have access to.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-path-trav-Dz5dpzyM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc691006");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc62415");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc62415");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

# Paranoid due to the existance of hotfixes
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', 'required_patch':'5'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', 'required_patch':'1'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc62415',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
