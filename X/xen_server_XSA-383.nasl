#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159892);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-28700");
  script_xref(name:"IAVB", value:"2021-B-0061-S");

  script_name(english:"No memory limit for dom0less domUs (XSA-383)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The dom0less feature allows an administrator to create multiple
unprivileged domains directly from Xen.  Unfortunately, the
memory limit from them is not set. This allows a domain to allocate
memory beyond what an administrator originally configured.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-383.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset 35ba323)';
fixes['4.12']['affected_ver_regex']  = "^4\.12([^0-9]|$)";
fixes['4.12']['affected_changesets'] = make_list('9e39b7f', '090986b',
  'e8f95a6', '90ae827', '4e5bf7e', 'b2f52a0', '22bd06c', '52ee570', 
  '1f5c237', 'aac5e50', '724eebc', 'dd59be6', 'd446431', '05e64a6', 
  '2f4cfe5', '0475382', 'bd52c7e', '7dadebd', 'c6c5f9d', 'ea20eee', 
  '99f2c46', 'd024fe1', 'e5f3be9', 'e318c13', 'ced413b', '95d23c7', 
  'aa8866c', '2c39570', '5984905', '5b280a5', '955c604', 'cd5666c', 
  '1df73ab', 'b406997', 'f66542f', '26764c5', 'b100d3e', '17db0ba', 
  '2e9e9e4', '652a259', 'b8737d2', '70c53ea', '4cf5929', '8d26cdd', 
  'f1f3226', 'cce7cbd', '2525a74', 'c8b97ff', '2186c16', '51e9505', 
  '4943ea7', '3c13a87', 'd4b884b', '7da9325', 'd6d3b13', '9fe89e1', 
  'd009b8d', '674108e', 'bfda5ae', '551d75d', '5e1bac4', 'f8443e8', 
  '655190d', 'f860f42', '9f73020', 'aeebc0c', 'f1a4126', 'b1efedb', 
  '4739f79', '0dbcdcc', '444b717', '544a775', 'c64ff3b', '8145d38', 
  '14f577b', '40ab019', '1dd870e', '5c15a1c', '6602544', '14c9c0f', 
  'dee5d47', '7b2f479', '46ad884', 'eaafa72', '0e6975b', '8e0c2a2', 
  '51eca39', '7ae2afb', '5e11fd5', '34056b2', 'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.4';
fixes['4.13']['fixed_ver_display']   = '4.13.4-pre (changeset bdb8480)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('985b3e5', '4d65fe9',
  '9d954c8', '53e797c', '89d40f0', 'f762403', 'ebeb9ec', '2357043', 
  '18fe877', '41200e0', '0ed0cdd', 'ecb4697', 'f50fbdd', '75bb9fe', 
  '4fa8b13', '85dc71b', '3cdc7b6', '32d5809', '41e8d5d', '27e08cb', 
  'f6f7690', '1f27fc4', 'a7de760', '1540a9a', '351c890', '3f3ebda', 
  '7907ab8', 'ddb3edb', 'e39050c', '235bfe8', '84bc28f', '9eece40', 
  '2c9da5f', '5aacd07', '64752a9', '948b7c8', '9bd6416', '97af34f', 
  'f799329', '0a3eb9b', 'd3d8a29', '83c0f6b', '9e3c8b1', 'def4352', 
  '95197d4', 'ef8b235', 'f17d848', 'fa5afbb', '4d54414', '287f229', 
  'e289ed6', '2841329', '33049e3', '53f4ce9', '8113b02', '0e711a0', 
  '21e1ae3', '4352a49', 'e93d278', '231237c', 'ca06bce', '5aef2c5', 
  '5de1558', 'e3bcd4d');

fixes['4.14']['fixed_ver']           = '4.14.3';
fixes['4.14']['fixed_ver_display']   = '4.14.3-pre (changeset c439f5e)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('66f5e86', 'b81187f',
  '29aeeda', '98bcd53', '6f4c214', '9685265', 'e4c2384', '1958758', 
  'fe6da09', '4a24451', '100b2e2', '8da1491', 'f7a9730', '61f2806', 
  '49299c4', 'b46af13', 'e32e184', 'bb731fd', 'c3cc6e2', 'bb9377a', 
  'f6aec84', '23d5e3d', '3cfccd7', '1ed3661', '645fcf8', '86c223c', 
  '79774e0', 'e06d0c1', '1dae9fd', '64d93d6', '3ae25fc', '665024b', 
  'ecd6b17', 'c6ee6d4', 'b6a8c4f', '45710c0', 'ee5425c', '4b4ee05', 
  '768138c', '0ff7f9c', 'fcf98ef', '51278ce', '766b1f4', 'e5bce3a', 
  '46ff245', '2665d97', '7053c8e', '5caa690', 'b046e05', '3f85493', 
  'ac507e0', 'ebfdf0c', '9d963a7', 'b15c24a', 'f23cb47', 'c2f78b4', 'a351751');

fixes['4.15']['fixed_ver']           = '4.15.1';
fixes['4.15']['fixed_ver_display']   = '4.15.1-pre (changeset 9bc2a68)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('8a8b16c', '2f6ebce',
  '9bfbde4', 'd40287a', '7850fe5', '9f44ed1', '27bc41d', 'd39756f', 
  '711aeb1', '34d141e', '29a6cf1', '92c8b92', '1beb196', '6bbdcef', 
  'abfbb29', 'c3cf33b', 'e0da171', 'c773053', '0f1002d', '00bd594', 
  '0e419e4', 'e3f5318', '4b60715', 'e949445', '9cb597a', '6165dcf', 
  'da659f6', '17dca16', '99633c5', '2b23bb6', 'dba7748', 'e98cacf', 
  '0e1407f', '61dea45', '429b0a5', '41f0903', '67f7989', 'e9709a8', 
  '1a68249', 'e6d098e', '16d2641', '7b658fd', '6ba107c', '2ba0d81', 
  '3581714', '0b80b34', 'd8a530e', '9892901', '3556dc6', '13ea8af', 
  '77069ea', 'ec457ac', '4586e64', '796d405', '0aabeb9', 'a339cea', 
  '874dac9', 'f034c96', '894636d', '12ebf0f', '35b5836', '8368f21', 
  '7044184', '0a64b18', 'eae0dfa', '89c6e84', '7c3c984', '6a7e21a', 
  'ee2b1d6', 'edeaa04', 'cacad0c', '3e6c1b6', '78a7c3b', '280d472', 
  'eb1f325', 'dfcce09', 'c129b5f', 'e2e80ff', '5788a7e', 'bb071ce', 
  '92dd3b5', 'baa6957', 'c86d8ec', 'e72bf72');

fixes['4.16']['fixed_ver']           = '4.16';
fixes['4.16']['fixed_ver_display']   = '4.16-unstable (changeset b75838a)';
fixes['4.16']['affected_ver_regex']  = "^4\.16([^0-9]|$)";
fixes['4.16']['affected_changesets'] = make_list('57f8785', '1e6706b',
  '2f5f0a1', '9516d01', '4cfab44', 'a0ffee6', '048de2c', '9e319e5', 
  'dbb9481', 'c8c6cd9', 'f929448', '3b38b1d', 'a1743fc', 'eb7518b', 
  '2faeb42', 'd3b05f9', '2d7f191', '834cb87', '036432e', 'e5ba9f7', 
  'aa44f3c', '71cf763', 'e26f810', 'bc2bdd4', '4817dbf', 'f38c859', 
  'e8b42a4', '2fac4e3', 'b6b672e', '24b0ce9', '664cc3c', 'd4c9845', 
  'e17abb2', '86e84e5', '8858dfa', '305f193', 'b11380f', '1d34553', 
  '2075b41', 'a095542', '1da6a07', '6ec9176', '15517ed', 'f9187cf', 
  '2a04f39', '74c48d4', '192aaf7', 'd6bdad3', 'efbd25c', '58ce57a', 
  '4b88b4b', 'b6fe410', '60649d4', '4eb1728', 'a9a34e2', 'c2f40d8', 
  'c9aa02e', '5d15f90', 'f01be29', '65ca66c', '1907cfc', 'a3a476f', 
  'a12ceae', 'ab4a830');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);