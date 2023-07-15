#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(168020);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id("CVE-2022-42321");

  script_name(english:"Xenstore: recursive operations causing xenstored stack exhaustion (XSA-418)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Xenstore: xenstored is using recursion for some Xenstore operations (e.g. for deleting a sub-tree 
of Xenstore nodes). With sufficiently deep nesting levels this can result in stack exhaustion leading 
to a crash.

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xenproject.org/xsa/advisory-418.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var fixes;
var app = 'Xen Hypervisor';
var app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.13']['fixed_ver']           = '4.13.4';
fixes['4.13']['fixed_ver_display']   = '4.13.4 (changeset 8c8a5b3)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('1cfbd25', 'ba1cff4',
  'd816b47', 'e2b7fa7', 'b97e59f', 'e6655e8', '2fdf874', 'e30f7c6',
  '0252d04', '723e248', 'c3c5f0a', '0135300', 'bc93157', 'c084ee8',
  'd71e4ec', '63dc2a1', '146b954', '7dc06ed', 'c17d491', '115156c',
  'b917d57', '8cd25ae', 'f859218', '5fa4f2c', 'e84ef3b', '2963ee5',
  '538b61b', 'cde36e0', '1761828', '6f31127', '95fe444', 'fcba6c7',
  '149ebf0', '5b66863', '3954468', '0be63c2', '042de08', '867fcf6',
  'e6b1e38', '2ae9bbe', '9992c08', 'eed4ef4', '3e7aa35', '6e537d3',
  '08eec20', '181ff7a', 'aa78910', '0021c26', '763f965', '4e38cc1',
  '5475195', 'bde3b13', 'd8a6930', 'c946524', 'f8614c7', '3feba68',
  '3c71016', 'ebe3f5d', '5994b73', 'fbf19ba', 'ba33672', '196b4f4',
  '10d8c56', '4b42462', 'a7e7287', '159e223', 'b8d573a', '074e388',
  'bf5f5e8', '8974821', '55e4c72', 'd43b47e', '4eddf13', 'f614e3c',
  '8a2cc1e', '14c5e0c', '87ff113', '413b083', 'a84bc5b', '1575075',
  'f9ae12f', 'e8c04e4', '8d9f361', 'fce392f', 'c7da430', '7669737',
  '3826ba5', 'fe97133', 'd64d466', 'a6902a6', '169a283', '454d535',
  'e6d6b5b', '7cfe357', 'ab37463', '92acf6b', '73e25ec', '235aa15',
  '33c1365', '81918ce', '650b888', '920e93d', '2ce2aec', '8ed46cc',
  '7b9814b', 'fbabb62', '47125f5', 'd99df7d', '03db213', '9a8804a',
  'ce49a1d', 'e48c787', '2d601a5', 'd0e2c27', 'd3c2319', 'd3cfb4b',
  'd94d006', '0b28069', 'b4bb02d', '6e2fc12');

fixes['4.14']['fixed_ver']           = '4.14.5';
fixes['4.14']['fixed_ver_display']   = '4.14.5 (changeset baa5f58)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('7f969f3', '1de79dc',
  '4e19742', '7d4c2de', '4d2fe1d', '2761f00', '55e23bf', '2cf1372',
  '8db5e6f', 'b8b3734', '7f5d36d', '3a67865', '276908c', 'f6a5a1d',
  '0bc44ec', '7c5316d', '0cc9d66', '36812ae', '3a7c46a', 'cc28906',
  '03889b6', '0406917', '93a9c3a', '82dfb67', '9ad9fde', '83b9da9',
  '3dafa5a', '36ed7fe', 'a03e2a3', '3530aa6', '00240cf', 'bd50953',
  'd0dd461', '96220ae', 'f25c377', '016de62', '6e5608d', '7d64fb5',
  '4220eac', 'fd688b0', 'e3b66e5', '804f83b', 'f90615c', 'fc10984',
  '9b5a7fd', 'b8f4a5d', '0bab3ab', '3163e34', '54b6eab', '9c975e6',
  '7a7406b', '4ed063a', '261b882', 'ef571a5', '87d90d5', '5bccfbb',
  '318d7bc', '0a6561b', 'd2f0cf7', '51e812a', '73465a7', 'b60c995',
  'e5fd508', '2d31666', 'f178689', 'a556377', '104dd46', 'c5f774e',
  '9f07848', '878e684', 'd7ebe3d', '82ba97e', '25c7ade', '204d4f1',
  '07fbed8', 'a72146d', '758f40d', 'c70071e', '17848df');

fixes['4.15']['fixed_ver']           = '4.15.4';
fixes['4.15']['fixed_ver_display']   = '4.15.4-pre (changeset 84674f2)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('9ead584', 'a95277e',
  '4096512', '83b6c51', 'b9a005b', '62755d0', '8012324', '607e186',
  '26faa6b', '64048b4', '9e5290d', 'fccdca8', 'bbb4cea', '9f89883',
  '4581622', '8fabb96', '4d30175', '1fc3ecc', '32efe29', '9c2e71f',
  '0113aac', 'aa29eb6', 'ccef72b', '1035371', '8ee7ed7', '3e51699',
  '97c251f', '56300e8', '53a77b8', '8999db8', 'b322923', '0d8bea4',
  '579e733', 'ee03d9b', 'ddab5b1', 'b68e3fd', 'a46f01f', '317894f',
  '9b8b65c', 'bff4c44', '6b035f4', '08bc78b', '9c51146', '1f679f0',
  'b833014', '916668b', '3885fa4', 'f8915cd', '6f948fd', '816580a',
  '0d23392', '9690bb2', '62e534d', '3ac64b3', '182f8bb', '19cf28b',
  'd176808', 'd638c20', '735b108', '7923ea4', 'd65ebac', 'bb43a10',
  '7ad38a3', 'c521504', '45336d8', '0c0680d', 'b03074b', '686c920',
  '7f055b0', '4f9b535', '1e26afa', '95f6d55', 'd24a10a', '0f3eab9',
  '0d805f9', '09fc590', '9acedc3', 'a075900', '104a54a', 'fba0c22',
  'c373ad3', '1e31848', '5efcae1', '8ae0b4d', 'df3395f', '1b9845d',
  'b64f1c9', '30d3de4', '4799a20', 'a095c6c', '5f1d017', 'c370994',
  'a2684d9', '2173d9c', '3859f3e', '35bf91d', '409976b', '2b29ac4',
  'f0d78e0', 'd7f5fb1', 'c707015', '2cfbca3', '156ab77', '505771b');

fixes['4.16']['fixed_ver']           = '4.16.3';
fixes['4.16']['fixed_ver_display']   = '4.16.3-pre (changeset 7682de6)';
fixes['4.16']['affected_ver_regex']  = "^4\.16([^0-9]|$)";
fixes['4.16']['affected_changesets'] = make_list('1514de3', 'f5a4c26',
  'c5a76df', '01ab491', '32ff913', '074b32e', '036fa87', 'c758765',
  'a026fdd', 'cec3c52', 'ea15678', '59981b0', '8b60ad4', 'a63bbcf',
  'ab21bb1', 'b0e95b4', 'b584b9b', '0a67b4e', '578d422', 'bce9857',
  '30c8e75', '2e406cf', '2d39cf7', '7017cfe', '717460e', '787241f',
  'b270ad4', '49344fb', 'd08cdf0', 'e26d6f4', 'f8af1a2', 'ce6aea7',
  '427e86b', '28ea39a', '62e7fb7', 'c229b16', '2f75e36', '08f6c88',
  '426a834', 'aac1085', '8f3f8f2', '96d26f1', '9fdb4f1', '88f2bf5',
  '481465f', '54f8ed8', 'd4a11d6', '02ab5e9', '5dae065', 'e5a5bde',
  '86cb374', '1bce7fb', '3f4da85', 'b956076', '4951007', '2b694dd',
  '4f3204c', 'c377cea', 'd4e971a', 'e8882bc', 'e85e2a3', '32cb815',
  '44e9dcc', '3a16da8', '914fc8e', '755a9b5', 'a603386', 'f5959ed',
  '943635d', '745e0b3', '28d3f67', '40e9daf', '3422c19', '8fc19c1',
  '937fdba', '8d9531a', '4aa3291');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
