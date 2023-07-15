#TRUSTED 5f83cc81646c8558705d5d6995353371a2f5009596041af4e39eadb8ccf3b579f6a2f5cda7cd76a935b6e0a667ce2fb579ee24734d551b1915c78a60791b9a23685ce2e7055e4eda03b9d8e06460cbfb6ca4acfc0b79ca41a3a173a1cf8b94dd8a1ddd51451b8408a3edfdd52083ce75c5252bfe9142a09b8e44036de83983e07fbd5c7b81e9ce56818230fa0498e3874fd50fd7733ae7cc39204308690ecc7874128c6b03303e3df737be41a4c3eff302e8dbdeffaa3f1f1351aa434f645690026e4c94ac0c96fda08c3b3ec52a07ad4dcbd52346d8667fb9b4782e8838e62616715a93bfb88a255df39102c453ac8652de1ef200a80a2b33a205be98ade23767034f50000fc1092ec82ef53916dcd017ebb7e9bc19cb634230bcc328233210b92f6aa2b33dece5007669426284a0b11bb7aee45d023f230df37c5da2df357d9f8282002006e80ee159ab1bc9dbcbd976e4a0b072c6bb8e63e776a172b2e545206390f582d75839ff5956f91daffdcce8d394c5ca952b04a7a052bb18b60b82f2b3b4a74198c1395580530b68892bbabdd13f503ce258d6cfe6695d3d757d679da5e7780b87107d9e5afff68d7c3620c3430b742449fd6b9ee061367a28dd46e5a9f1d7a689c85c3016fb47dc06d4c791d293866f32b849cbbc12f1095f4608be919748b47aa497c5bf0f630eab953350c6945b46883536a5862f779568b4ba
#TRUST-RSA-SHA256 376fa2665e110d4d2882b14b2e5251e7dfed4cab6237483bd6d00051c927b7ae388fa00d4333559feb2ec1e3f648395eb1aef00ceb4737ae7403cfff0ddcb7050387cf47a842a4afef9409c4f0a8e5d413c2cf33348ce10bba051e92356648ccb8ef21871dd2697e391e07ad3cacb967382262529378083f47eda5d3f20e168451ac5fd3e4f0f4b96772b06d9c7b7a681a446b91d18cc9ef25d28696517d69f8d8892f3568f4cb3c91fb63f034e3d5df3631bc23908b8094a0f26e27a58d4881ad409bfa5283dbbf379cddab7291cab908ea9154137af7c65347155b09bb3a9068cc8942ee89ffd895bd63fb8109439ed9ead011b376388b217e3ea76e81f6c15e6d26b88d61f84a4d8923b4fab2cd42676424695db4a5114f4d7765cf8f35cc0cfd2e2dfa8302cd268991dd488415ab95f3c268c2645b14a826cdfcaf7b8ca277f0310e1ac5d375dcbc916fb3d2ee68d8d5278efdb994a6377b62d2db8eb4760e65667092c3514a9be82793cfde8d8896f0b70364922f7b18b77963f5f402fc4f4710176db175792e1f743f9b3c8d80c5a636d8218a1b9851351322e5be9b0d9f5c674055a11116526d634e39c124692bb36f2d92dac005c30d5e57e1e743320d4b017670f7e215da7e154309330f731f3d95753932b889763418422dd73c19d547f003b9fe8dfff0c9eb4310613616e279f256503417bd2d4776e1783f4ff6
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161883);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-34793");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx46296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-dos-JxYWMJyL");
  script_xref(name:"IAVA", value:"2021-A-0526-S");

  script_name(english:"Cisco Firepower Threat Defense Software Transparent Mode DoS (cisco-sa-asa-ftd-dos-JxYWMJyL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service vulnerability. A denial 
of service (DoS) vulnerability exists in the TCP Normalizer. An unauthenticated, remote attacker can exploit this issue, 
via poisoning MAC address tables in adjacent devices and cause a network disruption.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-dos-JxYWMJyL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e81ea8c8");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx46296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx46296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(924);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.2'}
];

var config = 'show_firewall_mode';
var workarounds, extra, cmds, workaround_params;
var is_ftd_cli = get_kb_item('Host/Cisco/Firepower/is_ftd_cli');

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

  workarounds = make_list();
  workaround_params = '';
  extra = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG[config];
  cmds = make_list('show firewall');
}

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx46296'
);

if (!empty_or_null(extra))
  reporting['extra'] = extra;

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
