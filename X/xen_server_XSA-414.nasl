#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Inc.
##

include('compat.inc');

if (description)
{
  script_id(168021);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id("CVE-2022-42309");

  script_name(english:"Xenstore: Guests can crash xenstored (XSA-414)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Xenstore: a malicious guest can cause xenstored to use a wrong pointer during node creation in an error path, 
resulting in a crash of xenstored or a memory corruption in xenstored causing further damage. Entering the 
error path can be controlled by the guest e.g. by exceeding the quota value of maximum nodes per domain.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xenproject.org/xsa/advisory-414.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42309");

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
fixes['4.13']['fixed_ver_display']   = '4.13.4 (changeset 149ebf0)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('5b66863', '3954468',
  '0be63c2', '042de08', '867fcf6', 'e6b1e38', '2ae9bbe', '9992c08',
  'eed4ef4', '3e7aa35', '6e537d3', '08eec20', '181ff7a', 'aa78910',
  '0021c26', '763f965', '4e38cc1', '5475195', 'bde3b13', 'd8a6930',
  'c946524', 'f8614c7', '3feba68', '3c71016', 'ebe3f5d', '5994b73',
  'fbf19ba', 'ba33672', '196b4f4', '10d8c56', '4b42462', 'a7e7287',
  '159e223', 'b8d573a', '074e388', 'bf5f5e8', '8974821', '55e4c72',
  'd43b47e', '4eddf13', 'f614e3c', '8a2cc1e', '14c5e0c', '87ff113',
  '413b083', 'a84bc5b', '1575075', 'f9ae12f', 'e8c04e4', '8d9f361',
  'fce392f', 'c7da430', '7669737', '3826ba5', 'fe97133', 'd64d466',
  'a6902a6', '169a283', '454d535', 'e6d6b5b', '7cfe357', 'ab37463',
  '92acf6b', '73e25ec', '235aa15', '33c1365', '81918ce', '650b888',
  '920e93d', '2ce2aec', '8ed46cc', '7b9814b', 'fbabb62', '47125f5',
  'd99df7d', '03db213', '9a8804a', 'ce49a1d', 'e48c787', '2d601a5',
  'd0e2c27', 'd3c2319', 'd3cfb4b', 'd94d006', '0b28069', 'b4bb02d', '6e2fc12');

fixes['4.14']['fixed_ver']           = '4.14.5';
fixes['4.14']['fixed_ver_display']   = '4.14.5 (changeset d0dd461)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('96220ae', 'f25c377',
  '016de62', '6e5608d', '7d64fb5', '4220eac', 'fd688b0', 'e3b66e5',
  '804f83b', 'f90615c', 'fc10984', '9b5a7fd', 'b8f4a5d', '0bab3ab',
  '3163e34', '54b6eab', '9c975e6', '7a7406b', '4ed063a', '261b882',
  'ef571a5', '87d90d5', '5bccfbb', '318d7bc', '0a6561b', 'd2f0cf7',
  '51e812a', '73465a7', 'b60c995', 'e5fd508', '2d31666', 'f178689',
  'a556377', '104dd46', 'c5f774e', '9f07848', '878e684', 'd7ebe3d',
  '82ba97e', '25c7ade', '204d4f1', '07fbed8', 'a72146d', '758f40d',
  'c70071e', '17848df');

fixes['4.15']['fixed_ver']           = '4.15.4';
fixes['4.15']['fixed_ver_display']   = '4.15.4-pre (changeset ee03d9b)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('ddab5b1', 'b68e3fd',
  'a46f01f', '317894f', '9b8b65c', 'bff4c44', '6b035f4', '08bc78b',
  '9c51146', '1f679f0', 'b833014', '916668b', '3885fa4', 'f8915cd',
  '6f948fd', '816580a', '0d23392', '9690bb2', '62e534d', '3ac64b3',
  '182f8bb', '19cf28b', 'd176808', 'd638c20', '735b108', '7923ea4',
  'd65ebac', 'bb43a10', '7ad38a3', 'c521504', '45336d8', '0c0680d',
  'b03074b', '686c920', '7f055b0', '4f9b535', '1e26afa', '95f6d55',
  'd24a10a', '0f3eab9', '0d805f9', '09fc590', '9acedc3', 'a075900',
  '104a54a', 'fba0c22', 'c373ad3', '1e31848', '5efcae1', '8ae0b4d',
  'df3395f', '1b9845d', 'b64f1c9', '30d3de4', '4799a20', 'a095c6c',
  '5f1d017', 'c370994', 'a2684d9', '2173d9c', '3859f3e', '35bf91d',
  '409976b', '2b29ac4', 'f0d78e0', 'd7f5fb1', 'c707015', '2cfbca3',
  '156ab77', '505771b');

fixes['4.16']['fixed_ver']           = '4.16.3';
fixes['4.16']['fixed_ver_display']   = '4.16.3-pre (changeset 28ea39a)';
fixes['4.16']['affected_ver_regex']  = "^4\.16([^0-9]|$)";
fixes['4.16']['affected_changesets'] = make_list('62e7fb7', 'c229b16',
  '2f75e36', '08f6c88', '426a834', 'aac1085', '8f3f8f2', '96d26f1',
  '9fdb4f1', '88f2bf5', '481465f', '54f8ed8', 'd4a11d6', '02ab5e9',
  '5dae065', 'e5a5bde', '86cb374', '1bce7fb', '3f4da85', 'b956076',
  '4951007', '2b694dd', '4f3204c', 'c377cea', 'd4e971a', 'e8882bc',
  'e85e2a3', '32cb815', '44e9dcc', '3a16da8', '914fc8e', '755a9b5',
  'a603386', 'f5959ed', '943635d', '745e0b3', '28d3f67', '40e9daf',
  '3422c19', '8fc19c1', '937fdba', '8d9531a', '4aa3291');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_NOTE);
