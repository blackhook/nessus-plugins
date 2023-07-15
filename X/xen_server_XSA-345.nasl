##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149033);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2020-27672");

  script_name(english:"Xen x86 Race Condition Use-After-Free (XSA-345)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an issue
allowing x86 guest OS users to cause a host OS denial of service, achieve data corruption, or possibly gain privileges
by exploiting a race condition that leads to a use-after-free involving 2MiB and 1GiB superpages.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-345.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27672");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");

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

app = 'Xen Hypervisor';
app_info = vcf::xen_hypervisor::get_app_info(app:app);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 75a05da)';
fixes['4.10']['affected_ver_regex']  = "^4\.10([^0-9]|$)";
fixes['4.10']['affected_changesets'] = make_list('c334b87', '07ad8ff',
  '1719f79', 'f58caa4', 'f2befb6', '83b7f04', 'e081568', '7f0793a',
  '8fac37e', 'baf80b6', '5402540', 'f85223f', '635ae12', '3d14937',
  '4218b74', '93be943', '4418841', 'd9c67d3', '8976bab', '388e303',
  '0b0a155', '9df4399', 'fd57038', 'a9bda69', 'a380168', 'c1a4914',
  '6261a06', 'fd6e49e', 'bd20589', 'ce05683', '934d6e1', '6e636f2',
  'dfc0b23', '2f83654', 'bf467cc', '6df4d40', 'e20bb58', 'a1a9b05',
  'afca67f', 'b922c44', 'b413732', '3d60903', 'b01c84e', '1e722e6',
  '59cf3a0', 'fabfce8', 'a4dd2fe', '6e63a6f', '24d62e1', 'cbedabf',
  '38e589d', 'a91b8fc', '3e0c316', '49a5d6e', '6cb1cb9', 'ba2776a',
  '9d143e8', 'fe8dab3', '07e546e', 'fefa5f9', 'c9f9ff7', '406d40d',
  'e489955', '37139f1', 'fde09cb', '804ba02', 'e8c3971', 'a8c4293',
  'aa40452', '1da3dab', 'e5632c4', '902e72d', '6a14610', 'ea815b2',
  '13ad331', '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199',
  'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d',
  'a782173', '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 7912bbe)';
fixes['4.11']['affected_ver_regex']  = "^4\.11([^0-9]|$)";
fixes['4.11']['affected_changesets'] = make_list('f5ec9f2', 'ad7d040',
  '3630a36', '3263f25', '3e565a9', '30b3f29', '3def846', 'cc1561a',
  '6e9de08', '13f60bf', '9703a2f', '7284bfa', '2fe163d', '2031bd3',
  '7bf4983', '7129b9e', 'ddaaccb', 'e6ddf4a', 'f2bc74c', 'd623658',
  '37c853a', '8bf72ea', '2d11e6d', '4ed0007', '7def72c', '18be3aa',
  'a3a392e', 'e96cdba', '2b77729', '9be7992', 'b8d476a', '1c751c4',
  '7dd2ac3', 'a58bba2', '7d8fa6a', '4777208', '48e8564', '2efca7e',
  'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4-pre (changeset e461318)';
fixes['4.12']['affected_ver_regex']  = "^4\.12([^0-9]|$)";
fixes['4.12']['affected_changesets'] = make_list('1cec253', '03926de',
  '6888017', '0186e76', '0ca821f', 'cfd61e6', '2aa4864', '8e25d52',
  '9c2a027', '9dda47c', 'b8c9776', '253a1e6', '3e039e1', 'b2db007',
  '1dfd2e2', '76a0760', 'd28c52e', '8b8fff2', '320e7a7', '0446e3d',
  'a81e655', 'caebaf3', '76d9349', '81564c4', 'ff79981', '3186568',
  '40e0cf8', 'fbf016f', '8c1c3e7', '5bd49ca', 'e0bd899', 'c481b9f',
  '1336ca1', 'dca9cc7', '07fd5d3', '85ce36d', 'df9a0ad', '7cce3f2',
  '43258ce', 'a1aae54', 'df11056', '19e0bbb', 'd96c0f1', '653811e',
  '26072a5', 'b292255', '38dc269', '5733de6', 'd69f305', '8faa45e',
  '731bdaf', 'ec57b9a', 'a634229', '050fe48', '436ec68', '96e8aba',
  '7cdc0cf', 'd937532', '7641573', '7eed533', '74a1230', '946113a',
  '6182e5d', 'ad20170', '218a19b', 'aca68b9', '1f581f9', '4969f34',
  'ed44947', '2eb277e', 'b3af150', 'f769c99', 'bcdaffc', '2b10a32',
  'a022f36', 'dd49ddf', 'bc775d0', 'be5c240');

fixes['4.13']['fixed_ver']           = '4.13.2';
fixes['4.13']['fixed_ver_display']   = '4.13.2-pre (changeset 98ec971)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('7f5d676', 'a2c0c91',
  '8e7e585', '88f5b41', 'f63b20a', 'b015fbe', '54becf6', '43572a4',
  '2105429', 'a8122e9', 'e1364e0', '5867a14', '0537543', 'ae922b9',
  'f27980a', 'b7fcbe0', '42fcdd4', '286b353', 'b980319', 'aa1d9a7',
  'bd63ab5', '4fb1ad7', '4a0c174', '6ef4dad', 'c663fa5', '761e8df',
  '6469039', 'b908343', 'ac4ec48', 'a7f0434', '0861885', '9b367b2',
  'e182965', 'befa216', 'e9e72fb', 'b67bb90', 'fff1874', 'ec972cb',
  'd967a2b', '665f5c1', 'ddb6fd3', '378321b', '572e349', '0c8c10d',
  '493e143', '8b9be8f', 'f1055a2', '005d5ea', '1c7a98c', '2b34d8c',
  '56e117f', '7a76deb', '3e41b72', '9f7e8ba', 'cdd8f95', 'a9d46ba',
  '05ba427', '780d376', '31c5d84', '27d4f1a', '11ea967', '53bafb5',
  'b4afe05', '74ce65c', '0243559', '8ad99de', 'ea7e8d2', '350aaca',
  'c3eea2c', '0523225', '672976c', 'a6f2080', 'c437e06', '0a85f84',
  '85ac008', '7f6b66d', '04aedf4', 'f2ad77b', 'd61fef6', 'eccc242',
  '6bfb364', 'bdddd33', '7d57caa', 'd74eb10', '9eec3ee', 'd112db3', '333519f');

fixes['4.14']['fixed_ver']           = '4.14.1';
fixes['4.14']['fixed_ver_display']   = '4.14.1-pre (changeset 9e757fc)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('809a70b', 'b427109',
  'c93b520', 'f37a1cf', '5478934', '43eceee', '03019c2', '66cdf34',
  'ecc6428', '2ee270e', '9b9fc8e', 'b8c2efb', 'f546906', 'eb4a543',
  'e417504', '0bc4177', '5ad3152', 'fc8200a', '5eab5f0', 'b04d673',
  '28855eb', '174be04', '158c3bd', '3535f23', 'de7e543', '483b43c',
  '431d52a', 'ceafff7', '369e7a3', '98aa6ea', '80dec06', '5482c28',
  'edf5b86', 'eca6d5e', 'c3a0fc2', '864d570', 'afed8e4', 'a5dab0a',
  'b8c3e33', 'f836759');

fixes['4.15']['fixed_ver']           = '4.15';
fixes['4.15']['fixed_ver_display']   = '4.15-unstable (changeset f9c53bd)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('ba45ae4', '861f0c1',
  '3b49791', 'aace546', '0514a3a', '3b05512', '73f62c7', '5777a37',
  'dea460d', '1ce75e9', 'b733f8a', '08e6c6f', 'a7f0831', 'de6d188',
  '7b36d16', '25467bb', '0dfddb2', '17d192e', '40fe714', 'a7952a3',
  '04182d8', '6065a05', '6ee2e66', '27addcc', 'a8a85f0', '44ac57a',
  'f776e5f', '884ef07', 'e3daad6', 'f14a422', '6280558', '8752485',
  '6a34e67', '01d687c', 'c02fd5b', '3d77849', 'edc8d91', '47654a0',
  '8ea798e', '9e5a9d0', 'a95f313', 'c60f9e4', '534b3d0', '1b810a9',
  '8a62dee', '8a71d50', '4dced5d', '04be2c3', 'afef392', '8d25560',
  '25849c8', '0241809', 'a06d3fe', '1d246c7', '90c9f9f', '5144222',
  'fa06cb8', 'c65687e', '7a519f8', 'e4e6440', '9350859', '7f66c0d',
  '30bfa53', '1bc30c0', '35679b2', '345fd6d', '3600118', 'f5bdb4a',
  'dbe399b', '45264e0', '346b115', '8ef6345', '9ae1197', '59b27f3',
  '661b3e4', '6f6f07b', 'bb3d31e', '52e1fc4', '22b08b3', '23d4e0d',
  'bdb380e', '7f186b1', '77a0971', '3ae0d31', 'b22b9b9', 'bc01c73',
  '41aea82', 'de16a8f', '707eb41', '6df07f9', '11852c7', 'bfcc97c',
  '50a5215', '27de84d', '0d8d289', 'c739528', 'd72d615', 'e301a70',
  'd4bfa0c', 'f60ab53', '5dba8c2', 'cbe69ba', 'fca8d65', 'ecc9553',
  'b18b880', '358d57d', '7c6084c', 'c8b2488', '1e15dcf', '5be4ce0',
  '32a9ecc', '28804c0', 'f679038', '4bdbf74', '28fb8cf', 'f9ffd20',
  'fe41405', '643e2f3', '5bcac98', '61d4a04', 'af3c913', '5a37207',
  'a673280', '2785b2a', '8fe7b5f', 'e045199', 'c0ddc86', '8d385b2',
  '62bcdc4', '112992b', '910093d', 'e59ce97', 'beb5459', 'cb5e973',
  '8e76aef', '42317de', 'e71301e', '68a8aa5', '0229adb', 'b5622eb',
  '3eef6d0', 'dd2cfba', 'd4ed1d4', '5b61948', '6edcdb4', 'c7e3021',
  '5164e44', '18063d6', 'baa4d06', 'c729d54', '5a15c8a', '414d22c',
  '5152657', '84e848f', '322ec7c', '8a31c25', '39ab598', 'a4cbe0f',
  'b807cfe', 'fc4e79c', 'd16467b', '4f9a616', 'ed7cbd5', 'c8099e4',
  '6c5fb12', '5d45eca', 'b4e41b1', '0fcfe9d', 'e5a1b6f', 'c9476c4',
  '899316e', 'cc13835', '8900286', 'ba65a2f', '8efa465', '033b534',
  'a4c4b28', '6d2f1eb', '17f80e7', '5499e0f', '3cccdae', 'b72aa39',
  '82651ae', '0ca1af6', 'e69a56b', '3df903e', '6d0ec05', '8ab2429',
  'dd33fd2', 'e3dd624', 'af6c78d', '30f5e8a', '725588c', '7e0165c',
  '068000a', '256920d', 'f558931', '735749c', '6797d1e', '45397d4',
  '790f2df', 'a547703', '76020cc', '0c293ad', 'bb2ea7f', '7c273ff',
  '0b77395', '52dbd6f', '1e2d3be', 'b119100', '71039ed', '1be24cd',
  'ad0fd29', 'a5eaac9', 'f5b4426', '2454fa4', 'e527161', 'f4c1a54',
  '968bb86', '1814a62', '82c3d15', 'ac7a21c', 'fc4b1cb', '2c8fabb',
  '7dcf89d', '696c273', 'a609b65', '4d7bcd1', '7dcd33d', '9d207b8',
  '0dd40d6', 'c9e88d2', '4175fd3', '8cf2250', 'afe018e', 'e464742',
  'd400dc5', '8d99080', '0de9cbf', 'ddb2934', 'ded08cd', '09bf291',
  '097b6fe', 'bc44e2f', '725ef89', '314d8cc', 'e32605b', '70c52c4',
  '484fca9', '812c8e0', 'c7c6de0', '22cdff9', 'b51715f', 'bb13d93',
  '70fea87', 'f9d25fa', 'fff1b7f', 'd25cc3e', 'a623841', '86c076f',
  'd277004', '8b5b49c', 'a156887', 'de58ea4', '8856a91', '7a8d8bd',
  '1379576', 'de94e8b', '3473843', 'c297c94', 'e8f9d21', '888dd66',
  'ca7c88e', '858c0be', '3b418b3', 'f9d6734', '46a5f4f', 'a825751',
  'ba28efb', 'feab5bd', '80a868f', 'ba02a2c', '4d5b209', 'eee588b',
  '79c2d51', 'f0f2344', 'd501ef9', '2404e59', '9c7ff81', '529527b',
  '7207c15', '74ac7c8', '438c5ff', 'c4bdb64', '15bc9a1', 'e0f25d1',
  '9ce2bef', 'beb105a', '391a8b6', 'e44d986', '47b0bf1', '7a4dd36',
  '90c7eee', '16dcc13', 'd87c516', '5132a0a', 'b2bc1e7', 'dae7ea5',
  'a8ee9c4', 'b4175c6', 'e58a712', '062aad5', '96137cf', '6156cfe',
  '067e7b7', '3cb82fe', '5e6dc9b', 'd9dad35', '37b7b15', 'df8fb11',
  '2e98d0b', '4866056', '21de968', 'c9f9a72', 'fe49938', '9909532',
  '81fd0d3', 'ca24b2f', 'b6a907f', '132ece5', 'cb79dc1', 'a85f67b',
  '98bed5d', '64219fa', 'b071ec2', 'b6641f2', 'b9e9ccb', 'dc036ab',
  'ab5bfc0', '4489ffd', '1ee1441', '8899a28', 'c27a184', '0562cbc',
  'b2a6429', '82cba98', '55f8c38', '8a7bf75', 'ffe4f0f', '26707b7',
  'f3885e8', '69953e2', '057cfa2', 'a6ed77f', '6d49fbd', 'af05849',
  '139ce42', 'fc7f700', 'f6b78ae', '5fd152e', 'ef3b0d8', 'ded576c',
  '9ffdda9', '6720345', '5a4a411', '8c4532f', '6b6f064', 'fb024b7',
  '1745806', '32fa4ec', '83bb55f', '859447a', 'bf2a0ed', 'f8fe3c0',
  '1969576', 'f36f4bf', '165f3af', '3df0424');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
