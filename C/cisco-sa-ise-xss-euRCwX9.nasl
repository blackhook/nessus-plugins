#TRUSTED 7971476354b927188ca7785b4aecb673c7fe18fb285c8091ff7ec75579dcb071bb835cf6f0bbe10e758bfcbfb57ba6f84d71c41e7070d1c2c3af4464f560e51576d57170023f32ae6970424a9ec7a8c15e1e257c53fac843b49eba0eeead7c560bf364d95176be44fa46c061dc20f0bcbdfd714b3719d4178dc6236b0ca263ce941d73a631d99e413191644612025ecd7326794dd5f0b90882ffa8687419b61f130e2f4ae4d834729cc4afab7dc6e948ab388459b6b111fd4f9fe0507efb8d5b70b04518a86847486ee84ab0da12e02149b9ff1f6e103e83b4d4941bb3ffe686f3a107e925b44f2dde6ec82f79579e522a69cdca42c9ebf29a6fc2682b32adbc5b17aa869c51e36956adc818ac113b4989f2f637588d45389ace5ea09cad51aec8bc93e69bb242a3be77df7aeac2b603df70614a7eb49868c4418117485ad72e8d52cff4790b4654860355f7af15fb76e51df4e43cf03c0ca5a29630f154e3d27e404c739868907ee01fb2e081b108a701e6bdca314518f2f663b57c7fcba5690549290d4229b5b2b852e5f96be932f7cb1ccd1479235a3aa5fc331b1943767520e49c2d25f5e8e19116c3c073e09cd66794d5b90bf57ed42a2fa220e31c219127cb3409dd317aed9648661bcbe319decfd5a341ffc649940a5f6d0f8bd8824152d8b478d801dff7fb2b6b3145b85de6527290f97ba223ef76ef9b38cafe3ff1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142593);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3551");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv01681");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-euRCwX9");
  script_xref(name:"IAVA", value:"2020-A-0500-S");

  script_name(english:"Cisco Identity Services Engine XSS (cisco-sa-ise-xss-euRCwX9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a cross-site scripting
(XSS) vulnerability due to the web-based management interface not properly validating user-supplied input. An
unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute
arbitrary script code in a user's browser session.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-euRCwX9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94861c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv01681");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv01681.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# Affected versions are 2.6 and 2.7
# Cisco BID lists 2.6.0.156-Patch8 as fixed
# Cisco BID lists 2.7.0.356-Patch3 as fixed

vuln_ranges = [
  {'min_ver':'2.6', 'fix_ver':'2.6.0.156'}, 
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}
];

required_patch = '';
if (product_info['version'] =~ "^2\.6\.")
  required_patch = '8';
if (product_info['version'] =~ "^2\.7\.")
  required_patch = '3';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv01681',
  'fix'      , 'See vendor advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
