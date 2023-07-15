#TRUSTED 1866dd3121350eeed6c70e244c712e1df8187b478a37dc85dfb11d87b3e4f8a0e433a07d57f79e21e375c39f42b43b0af2459571479893ae2c1c993eb571ca7c51c57de53ae29526112eeacf78b1767af99eee4c1e333daa2ad736fe9f4582bc6936db4faadcde604048ce59b72ad25a6eab4ae3d0ed76db948227dae554848947b949b5153b5e0174edeead185da25b649d77bca037959a896be0f3419dbd702db3b01112c0b31740a780965a201ea6c475a2365f0a84cd536eb57f385dd2ecc76705fe8707e7b53197300c8af90d88556c7c0554e25353c0d8b747cc342e3cf3cddc9c1421947822c6ec243e2daf692a77a77bc87465e9bc86816778dc298c9335763674264439d6536fb9f4276980f61cd5f3da0c2389fcdee0753048d21449e1939ec01d5e08258ed6379828f460c7725a415d729bd4e65b3eec80efb743d711371107f42a34f752797dd607110a9d9779aeb91dd863780d2c07c53f1a45938b10746008730701052316fe980977eda4f88921080416bc298d0d66c27878089ea65270e9f03dfb997bb662be8c59bd4a207898db793ac9ad27e235c3f92efa5dc21fabfc3dbd191aed22a3ea7d11afad9e0f6e383b15016ec5977e600e28f1687572313dd826a64b148f99ec934cec15951fb5e490e950c4382dd5ec0c92778403820c42a1d402cb73727954d011ec1f4b813d03923fe2880b782da7fc42
#TRUST-RSA-SHA256 6c5c8cc697c5843fb5d1cdd8b871c53a42edfbf89fcb49fed8364ddaf287c2a484090fef3426ee03fc12bc425c7336a0ae3e75ab9d41c3e9bf518fd21251d451f74be905637b7fe3a2cf890ec2dc9c59565e34774d7510fb9c9c747db1bc28706681bddeeeeb966e30e5b204316f367d33a21fe4994df464c4f1695e58c7b0f54e0aaa51c05154ecbd821c8d338d8f3a62d3fbbc7447c82de5a24333dee22c0a9ae6f2a5ad16cc400ede6366002073acd6810adbf9ac249fb9ddbfa89316c138d2360293fa308c3416c02beefdc5f451df9d275895cafaf00f39979f51b679aa30117a1f23b9bb99dd8fc5763ea5b674b4c51789152072b92b9cde4913f6ae50c0f4affcdce10088214f0e5ef2227538fb16ea9bde2e0a4df625bcb2be591619d272916c47bd6f8d1fa603b5ec638b3b3e95477e00acfaaf60faf900ac0f6784763f5237dc53fb555e50f06407e3b15132ca43087cc09f1cf81d451bd80ddb1f4e6400be13ea90755d42b6fe7033e07b756bbd54e1b4aa505da9447409f6fd22aba435e9df22e8eb080293e0dba101f58f929b8b86884f49169d1defbf2c00e1522d235f92937ecab727c743cb9311e55737f22ea1797a2d3f84e6ba4b7325c6f94a35cb790853e6ae758e0f12e94e70f4a50a68a880ba09edb7ab68b1fe8a54708758c63e24e81044b0e05b6b7d26646d152fc4d175ab732efb71f7791dd8e4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124172);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0296");
  script_bugtraq_id(104612);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi16029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-asaftd");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0741");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco FTD Web Services DoS (cisco-sa-20180606-asaftd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Firepower Threat Defense (FTD) Software is missing a vendor-supplied security patch. It is,
therefore, affected by a vulnerability in the web interface due to improper validation of the HTTP URL. An
unauthenticated, remote attacker can exploit this, via a specially crafted HTTP request, to cause a DoS condition or
unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c235f451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi16029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20180606-asaftd.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0296");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'Cisco Firepower Threat Defense';
app_info = vcf::get_app_info(app:app);
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', app);

ver = product_info['version'];
model = product_info['model'];

if (
  model !~ '^1000V' && # 1000V
  model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  model !~ '^55[0-9][0-9]' && # 5500
  model !~ '^55[0-9][0-9]-X' && # 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model != 'v' &&                       # ASAv
  model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SSA
  model !~ '^93[0-9][0-9]($|[^0-9])'    # Firepower 9300 ASA
) audit(AUDIT_HOST_NOT, 'an affected Cisco FTD product');


if (ver =~ '^6.(0|1.0)' && (model =~ '^41[0-9][0-9]($|[^0-9])' || model =~ '^93[0-9][0-9]($|[^0-9])'))
  fix = 'Cisco_FTD_SSP_Hotfix_EI-6.1.0.7-2.sh';
else if (ver =~ '^6.(0|1.0)')
  fix = 'Cisco_FTD_Hotfix_EI-6.1.0.7-2.sh';
else if (ver =~ '^6.2.[12]')
  fix = '6.2.2.3';
else if (ver =~ '6.2.3')
  fix = '6.2.3.1 / 6.2.3-85 (Software image for FTD Virtual for the Microsoft Azure Cloud) / 6.2.3-85.0 (Software image for FTD Virtual for the AWS Cloud)';

vuln_ranges = [
  {'min_ver' : '6.0', 'fix_ver' : '6.1.0.7'},
  {'min_ver' : '6.2.1', 'fix_ver' : '6.2.2.3'},
  {'min_ver' : '6.2.3', 'fix_ver' : '6.2.3.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , ver,
  'bug_id'   , 'CSCvi16029',
  'fix'      , fix
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

