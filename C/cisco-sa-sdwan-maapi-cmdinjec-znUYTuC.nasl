#TRUSTED 78f3afcabc21f1850b0474b75ed050fa7711e9de3da0f829dc256bf344f37670d7b8eec7f91f55b9b7865b0590bb426c7b7d61f0589d8ba1c57344e221ca89147d6672cb5ec943ae5b3f27ff6fa40b1011b3dcfbc10be2aa53ed339671995d072d6ead6fdbb6f4e7414774d261a285dfbd7d1ba929f72cdcac3beb3475814beb8cc6abd8d27e3ece1431c7e04f2c2172c4f39fad6405bb8f470db2918902e69768965325c68e72142e871a943b2b948e3b3227bbfc5072bdbae0dedd94b79bf8e9c93fe8e53874bbe7cf4ad6fe004026e7af9642446230446b297cca9dbc5493c0baf33aad1019759e478e19e2eca599ab0183c6e831e717938839a52eaa74cf0381398d96f72683460d0fc29eb21deb827f44f9d769781ce2b6809d1d700c15b970d84317ff305553178098e3b232a160302813eed69578a4d288aad9289a9e6040be0b624e0a3f72297184f21dd6a2e4eef7a4636266ac7ebc174a7b77055f1101c75e7e29abd79dcd341a52ef2f9185cf66501c0d5f652bacbf99ea93d0460d4cf983a69d126d886faa5d0f2f0e75c0f21e6b732d3030dbd2cc36467f09447e75511c19088151d153a3c4d0ad5b399740593ccc00d4b891eb9a1c7710c51cfa9ff5e9d4c19e8e1135aa26e80ebbc748bc6fce72aa5ce949c6c3e8fbe21da223a88005673b14a1d6d65a8385fac56dbd0581cb3bfc50f6042282614f959ef2
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153551);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-34726");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs98414");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-maapi-cmdinjec-znUYTuC");
  script_xref(name:"IAVA", value:"2021-A-0435");

  script_name(english:"Cisco SD-WAN Software Command Injection (cisco-sa-sdwan-maapi-cmdinjec-znUYTuC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to inject
    arbitrary commands to be executed with root-level privileges on the underlying operating system of an
    affected device. This vulnerability is due to insufficient input validation on certain CLI commands. An
    attacker could exploit this vulnerability by authenticating to an affected device and submitting crafted
    input to the CLI. The attacker must be authenticated as an administrative user to execute the affected
    commands. A successful exploit could allow the attacker to execute commands with root-level privileges.
    (CVE-2021-34726)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-maapi-cmdinjec-znUYTuC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d45939d9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs98414");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs98414");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34726");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.4.6' },
  { 'min_ver' : '19.2', 'fix_ver' : '19.2.3' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var version_list = make_list(
  '18.4.302.0',
  '18.4.303.0',
  '19.2.097',
  '19.2.099'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvs98414',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
