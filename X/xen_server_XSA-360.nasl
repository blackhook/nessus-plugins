##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149086);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/30");

  script_cve_id("CVE-2021-3308");

  script_name(english:"Xen IRQ Vector Leak DoS (XSA-360)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service (DoS) vulnerability. An x86 HVM guest with PCI pass through devices can force the allocation of all IDT
vectors on the system by rebooting itself with MSI or MSI-X capabilities enabled and entries setup. Such reboots will
leak any vectors used by the MSI(-X) entries that the guest might had enabled, and hence will lead to vector exhaustion
on the system, not allowing further PCI pass through devices to work properly. HVM guests with PCI pass through devices
can mount a DoS attack affecting the pass through of PCI devices to other guests or the hardware domain. In the latter
case, this would affect the entire host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-360.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app = 'Xen Hypervisor';
var app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset cce7cbd)';
fixes['4.12']['affected_ver_regex']  = "^4\.12\.[34]([^0-9]|$)";
fixes['4.12']['affected_changesets'] = make_list('2525a74', 'c8b97ff',
  '2186c16', '51e9505', '4943ea7', '3c13a87', 'd4b884b', '7da9325',
  'd6d3b13', '9fe89e1', 'd009b8d', '674108e', 'bfda5ae', '551d75d',
  '5e1bac4', 'f8443e8', '655190d', 'f860f42', '9f73020', 'aeebc0c',
  'f1a4126', 'b1efedb', '4739f79', '0dbcdcc', '444b717', '544a775',
  'c64ff3b', '8145d38', '14f577b', '40ab019', '1dd870e', '5c15a1c',
  '6602544', '14c9c0f', 'dee5d47', '7b2f479', '46ad884', 'eaafa72',
  '0e6975b', '8e0c2a2', '51eca39', '7ae2afb', '5e11fd5', '34056b2',
  'fd4cc0b', '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.3';
fixes['4.13']['fixed_ver_display']   = '4.13.3-pre (changeset e416193)';
fixes['4.13']['affected_ver_regex']  = "^4\.13\.[123]([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('1dd5645', 'bbce51a',
  '95b5283', 'dc36f72', '0c78a9d', '10c7c21', 'bb534d6', '16d0dc0',
  '13afcdf', 'd39eb6f', 'a2f7ae1', 'd6a55f1', 'c6196ca', '18c0abb',
  '782aa4b', '6aea4d8', '12a41a8', '4056c3e', 'f4d84a2', '65c187f',
  '2df79ff', 'b693968', '52a0a8f', '60e3727', '8cc0a86', 'ef765f6',
  'b8f23da', 'ee416da', '1819c9d', '1ab192f', '2007c63', '2948458',
  '4959626', '2fa586c', 'b530227', '74c5729', 'a1d8a6c', 'd064b65',
  '4f30743', '72031bc', '7d6f52d', 'ec09215');

fixes['4.14']['fixed_ver']           = '4.14.2';
fixes['4.14']['fixed_ver_display']   = '4.14.2-pre (changeset 4170218)';
fixes['4.14']['affected_ver_regex']  = "^4\.14\.";
fixes['4.14']['affected_changesets'] = make_list('9028fd4', '7f99c05',
  'cad784f', 'e44321d', 'a3509dc', '5f9b0f9', 'a514c5e', '1b09f3d');

fixes['4.15']['fixed_ver']           = '4.15';
fixes['4.15']['fixed_ver_display']   = '4.15-unstable (changeset 5842788)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('e8adbf6', '2bb32b8',
  '74cbc59', '3d64806', '7936671', '3487f4c', 'a59e56b', 'b7f4628',
  '0f4fd0d', '5e53349', '4d0fbc2', '8e4f3b6', '01ce02c', '3a0b215',
  'cf2a566', 'cb34a2f', '1839011', '9712753', 'b066d57', '8cec5d0',
  'd6627cf', '35d2960', '7c9f816', 'db9c4ad', 'cc83ee4', '36457d7',
  'ced9795', 'aa4b9d1', '8868a0e', '29a6082', '935e5fb', 'f7918dc',
  '1997d37', '461144c', 'f589765', '17d0255', 'c92c9f8', '84a37d2',
  '01d411f', 'ff20706', '1bdd123', 'd975164', '0293fd2', '896128e',
  'bc70924', '67848a2', '2de2674', 'ec6c5d3', '414be7b', '0db1ded',
  'edad4c7', '0e97d99', '17b2ddf', 'faa0ab2', '8fc9852', 'e945fcf',
  '654c917', 'b4b0a86', '7cf8a2d', '1376ef9', '2039ebf', '4e70f31',
  'ce59e3d', 'b468b46', '5b77245', '1806d08', '8511cc9', '570065b',
  '3e6c560', '762c389', '5fa9a14', '6721f01', 'ede2583', '994f647',
  'eb298f3', '925fdb0', '1977cd7', '37c709a', 'a625c33', 'c58654c',
  'd581cf8', '2c5119d', 'edf5b22', '22deecf', '7a83d9d', 'c992efd',
  'c711553', '4e421ad', 'bbf71e9', '4f022a2', 'fa679ef', '6fbb412',
  '4bac861', '0f7bcaf', '04b0903', 'b06ffca', 'b1c014a', 'bb4ef15',
  '7d2d7a4', '16ca5b3', '0f089bb', '6ea3e32', '73ff361', '8f81064',
  '07b9ace', '3669a1c', '2d66a1f', '9cfdb48', 'a9f1f03', '7ba2ab4',
  '62dde2c', '1516ecd', '8cefa4b', '83736c5', '98d4d6d', '8dfeef4',
  'e18dadc', 'd4f699a', 'e93c371', 'ee41b5c', '1a050d6', '8c8938d',
  'ffa9d29', 'd162f36', '6131dab', '357db96', '8009c33', '173ae32',
  'f772b59', '7c3af56', 'c542122', '3b1d8eb', '65fdf25', '26dfde9',
  'f301f9a', '7a3b691', 'fccaa4d', 'b44eb6d', '7b532ee', 'e1681ce',
  'f6e1d85', 'a9afe77', 'c5f8e7d', '335ddd8', '3a51115', '8c5e5e8',
  'dbc1e72', '641723f', 'fbb2b92', '70fadc4', 'fe733fa', '2474e53',
  'cbc8634', 'd81133d', 'ac6a0af', '5a324e1', '7dcaffc', '2c2c941',
  '033a806', '8bf0fab', 'e114165', '93c16ae', '5ab684c', '66c2fbc',
  'f73c5dd', '96ed6ff', '929f231', '8bc342b', '3085930', '581abb6',
  '413fd4e', 'c00da82', '7499b22', 'f8cfb85', '4951b9e', 'fe91a3a',
  'b5429d6', 'a825ab3', '33e1c5a', 'd8cba53', '0fdb48f', 'fce6999',
  '6c25909', 'e43780f', '8862cb6', '8b90e31', '924bf8c', 'c6dc730',
  '3e6944b', '904148e', 'c5e6365', 'dc8b01a', 'ca85682', 'e6ebd39',
  '058e469', 'e3df3fb', '2a3f8d1', '491a077', 'd2fa370', '5a3f7a0',
  'bf07039', 'c46eff9', '4963063', '34f0083', 'ff3d2df', 'cf4116c',
  '0911dfa', '67bfd6c', 'f40d933', 'e47f438', '190ddd3', '53dabb1',
  '1e58156', '297f209', 'fa2307b', 'd3f8c08', '0bfb210', '09a4146',
  '705c7d8', 'feeafa0', '8e0fe4f', 'a69583c', '777e359', '0919030',
  '4b0e0db', '881966d', '841f660', 'd5ce1f6', '30d430b', '3ec53aa',
  '826a6dd', 'd218fb1', 'b7c3330', 'e373bc1', '5e66635', 'a00b271',
  'bfc78f7', '1e83722', '948719f', '30d3cc4', '9afa867', 'b412468',
  '3a3f4f0', '728acba', '33c1a1c', '905d931', 'c811706', '7c8946d',
  '0fb6dbf', 'be3755a', 'f1b920b', 'd290337', 'ba6e78f', '8be06d7',
  'aec4688', 'cabf60f', 'b2a88b2', '1283ad8', '9f5ce6e', 'b00d057',
  '3ae469a', '71ac522', '43803dc', 'f7d7d53', 'f7e77e5', 'fcdb988',
  '25ccd09', '181f2c2', '500516f', '8041317', '758fae2', '1e6d7bd',
  'fd7479b', '9b156bc', '8147e00', '2291ad4', '510cdda', 'f390941',
  '8b6d55c', '6befe59', '1277cb9', 'b659a5c', '846d22d', 'dee7d98',
  'bebb491', '318a917', '0ff2c7e', '9a3c25b', '1965c17', '415f904',
  '7872b49', '22e323d', '5200fba', '2743174', '665c940', 'f2c620a',
  'dc5616e', 'a7ab52f', '7aa7629', '192b45e', '5505f5f', '6963422',
  '53bacb8', '628e1be', 'e6e85b6', 'f5cfa09', 'db1a9fd', 'b5ad37f',
  '5f2df45', '3059178', '0a5e0ce', 'cd800ce', '4196b15', '8aac8e0',
  '2a5f9f6', 'e19bcb6', 'c3453a2', '957708c', 'e006b2e', '2b8314a',
  '9ff9705', 'c0d3cc9', '5816d32', '8587160', '7056f2f', '9c2bc0f',
  'dac867b', '4d625ff', '1c4aa69', 'ca56b06', 'b1b4f95', '177cf86',
  'a780b17', 'e0daa27', '92bc186', '0b84131', '8ac7e45', '6e2ee3d',
  '82c0d3d', 'f9179d2', '26a8fa4', '1fd1d4b', '33d2bad', '16a2096',
  '055e1c3', '964781c', '20cd1be', '2a75837', '92abe14', '4ddd649',
  '06f0598', '9af5e2b', '588756d', '4664034', '154137d', 'f899554',
  '56c1aca', '70cf8e9', '032a96e', '6ca7082', '710f62c', 'b76c3a1',
  '451a909', '5bc8428', 'dcbd1d8', '83432ad', 'f9c53bd', 'ba45ae4',
  '861f0c1', '3b49791', 'aace546', '0514a3a', '3b05512', '73f62c7',
  '5777a37', 'dea460d', '1ce75e9', 'b733f8a', '08e6c6f', 'a7f0831',
  'de6d188', '7b36d16', '25467bb', '0dfddb2', '17d192e', '40fe714',
  'a7952a3', '04182d8', '6065a05', '6ee2e66', '27addcc', 'a8a85f0',
  '44ac57a', 'f776e5f', '884ef07', 'e3daad6', 'f14a422', '6280558',
  '8752485', '6a34e67', '01d687c', 'c02fd5b', '3d77849', 'edc8d91',
  '47654a0', '8ea798e', '9e5a9d0', 'a95f313', 'c60f9e4', '534b3d0',
  '1b810a9', '8a62dee', '8a71d50', '4dced5d', '04be2c3', 'afef392',
  '8d25560', '25849c8', '0241809', 'a06d3fe', '1d246c7', '90c9f9f',
  '5144222', 'fa06cb8', 'c65687e', '7a519f8', 'e4e6440', '9350859',
  '7f66c0d', '30bfa53', '1bc30c0', '35679b2', '345fd6d', '3600118',
  'f5bdb4a', 'dbe399b', '45264e0', '346b115', '8ef6345', '9ae1197',
  '59b27f3', '661b3e4', '6f6f07b', 'bb3d31e', '52e1fc4', '22b08b3',
  '23d4e0d', 'bdb380e', '7f186b1', '77a0971', '3ae0d31', 'b22b9b9',
  'bc01c73', '41aea82', 'de16a8f', '707eb41', '6df07f9', '11852c7',
  'bfcc97c', '50a5215', '27de84d', '0d8d289', 'c739528', 'd72d615',
  'e301a70', 'd4bfa0c', 'f60ab53', '5dba8c2', 'cbe69ba', 'fca8d65',
  'ecc9553', 'b18b880', '358d57d', '7c6084c', 'c8b2488', '1e15dcf',
  '5be4ce0', '32a9ecc', '28804c0', 'f679038', '4bdbf74', '28fb8cf',
  'f9ffd20', 'fe41405', '643e2f3', '5bcac98', '61d4a04', 'af3c913',
  '5a37207', 'a673280', '2785b2a', '8fe7b5f', 'e045199', 'c0ddc86',
  '8d385b2', '62bcdc4', '112992b', '910093d', 'e59ce97', 'beb5459',
  'cb5e973', '8e76aef', '42317de', 'e71301e', '68a8aa5', '0229adb',
  'b5622eb', '3eef6d0', 'dd2cfba', 'd4ed1d4', '5b61948', '6edcdb4',
  'c7e3021', '5164e44', '18063d6', 'baa4d06', 'c729d54', '5a15c8a',
  '414d22c', '5152657', '84e848f', '322ec7c', '8a31c25', '39ab598',
  'a4cbe0f', 'b807cfe', 'fc4e79c', 'd16467b', '4f9a616', 'ed7cbd5',
  'c8099e4', '6c5fb12', '5d45eca', 'b4e41b1', '0fcfe9d', 'e5a1b6f',
  'c9476c4', '899316e', 'cc13835', '8900286', 'ba65a2f', '8efa465',
  '033b534', 'a4c4b28', '6d2f1eb', '17f80e7', '5499e0f', '3cccdae',
  'b72aa39', '82651ae', '0ca1af6', 'e69a56b', '3df903e', '6d0ec05',
  '8ab2429', 'dd33fd2', 'e3dd624', 'af6c78d', '30f5e8a', '725588c',
  '7e0165c', '068000a', '256920d', 'f558931', '735749c', '6797d1e',
  '45397d4', '790f2df', 'a547703', '76020cc', '0c293ad', 'bb2ea7f',
  '7c273ff', '0b77395', '52dbd6f', '1e2d3be', 'b119100', '71039ed',
  '1be24cd', 'ad0fd29', 'a5eaac9', 'f5b4426', '2454fa4', 'e527161',
  'f4c1a54', '968bb86', '1814a62', '82c3d15', 'ac7a21c', 'fc4b1cb',
  '2c8fabb', '7dcf89d', '696c273', 'a609b65', '4d7bcd1', '7dcd33d',
  '9d207b8', '0dd40d6', 'c9e88d2', '4175fd3', '8cf2250', 'afe018e',
  'e464742', 'd400dc5', '8d99080', '0de9cbf', 'ddb2934', 'ded08cd',
  '09bf291', '097b6fe', 'bc44e2f', '725ef89', '314d8cc', 'e32605b',
  '70c52c4', '484fca9', '812c8e0', 'c7c6de0', '22cdff9', 'b51715f',
  'bb13d93', '70fea87', 'f9d25fa', 'fff1b7f', 'd25cc3e', 'a623841',
  '86c076f', 'd277004', '8b5b49c', 'a156887', 'de58ea4', '8856a91',
  '7a8d8bd', '1379576', 'de94e8b', '3473843', 'c297c94', 'e8f9d21',
  '888dd66', 'ca7c88e', '858c0be', '3b418b3', 'f9d6734', '46a5f4f',
  'a825751', 'ba28efb', 'feab5bd', '80a868f', 'ba02a2c', '4d5b209',
  'eee588b', '79c2d51', 'f0f2344', 'd501ef9', '2404e59', '9c7ff81',
  '529527b', '7207c15', '74ac7c8', '438c5ff', 'c4bdb64', '15bc9a1',
  'e0f25d1', '9ce2bef', 'beb105a', '391a8b6', 'e44d986', '47b0bf1',
  '7a4dd36', '90c7eee', '16dcc13', 'd87c516', '5132a0a', 'b2bc1e7',
  'dae7ea5', 'a8ee9c4', 'b4175c6', 'e58a712', '062aad5', '96137cf',
  '6156cfe', '067e7b7', '3cb82fe', '5e6dc9b', 'd9dad35', '37b7b15',
  'df8fb11', '2e98d0b', '4866056', '21de968', 'c9f9a72', 'fe49938',
  '9909532', '81fd0d3', 'ca24b2f', 'b6a907f', '132ece5', 'cb79dc1',
  'a85f67b', '98bed5d', '64219fa', 'b071ec2', 'b6641f2', 'b9e9ccb',
  'dc036ab', 'ab5bfc0', '4489ffd', '1ee1441', '8899a28', 'c27a184',
  '0562cbc', 'b2a6429', '82cba98', '55f8c38', '8a7bf75', 'ffe4f0f',
  '26707b7', 'f3885e8', '69953e2', '057cfa2', 'a6ed77f', '6d49fbd',
  'af05849', '139ce42', 'fc7f700', 'f6b78ae', '5fd152e', 'ef3b0d8',
  'ded576c', '9ffdda9', '6720345', '5a4a411', '8c4532f', '6b6f064',
  'fb024b7', '1745806', '32fa4ec', '83bb55f', '859447a', 'bf2a0ed',
  'f8fe3c0', '1969576', 'f36f4bf', '165f3af', '3df0424');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
