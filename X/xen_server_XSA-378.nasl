#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159518);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-28694", "CVE-2021-28695", "CVE-2021-28696");
  script_xref(name:"IAVB", value:"2021-B-0061-S");

  script_name(english:"Xen IOMMU page mapping issues on x86 (XSA-378)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host 
 is affected by multiple vulnerabilities in IOMMU page mapping on x86.
 Both AMD and Intel allow ACPI tables to specify regions of memory which should be left untranslated, which typically
 means these addresses should pass the translation phase unaltered. While these are typically device specific 
 ACPI properties, they can also be specified to apply to a range of devices, or even all devices. On all systems with 
 such regions Xen failed to prevent guests from undoing/replacing such mappings.

  - On all systems with such regions Xen failed to prevent guests from undoing/replacing such 
    mappings. (CVE-2021-28694)

  - On AMD systems, where a discontinuous range is specified by firmware, the supposedly-excluded 
    middle range will also be identity-mapped. (CVE-2021-28695)

  - On AMD systems, upon de-assigment of a physical device from a guest, the identity mappings would 
    be left in place, allowing a guest continued access to ranges of memory which it shouldn't have access to anymore. (CVE-2021-28696)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-378.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

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

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4 (changeset 8c02a49)';
fixes['4.11']['affected_ver_regex']  = "^4\.11([^0-9]|$)";
fixes['4.11']['affected_changesets'] = make_list('f5ec482', '2468d8e',
  'ba79e52', 'fb23026', '82e93b8', 'c18e200', '3da2f2b', '66f400c', 
  '2e01b8f', 'a7cb4af', '42fcb07', 'd2356c3', 'ef32c7a', '7937627', 
  '944da2f', '9f8bf2a', 'dc3e544', '89d3cc6', '37518c2', 'b1e46bc', 
  '8bce469', '1d5581d', '9b299ec', '131d98f', 'f4adc4d', 'efe63c5', 
  'a0ae69c', '04dd325', 'e806708', '4288da8', '939164f', '76d369d', 
  '80cad58', '1c7d984', 'f9090d9', '310ab79', '2d49825', '24f7d03', 
  'f1f3dee', '1e87058', '4cc2387', '4053771', 'b3f4121', 'e36f81f', 
  '1034a45', '7791d2e', '5724431', '495e973', '771a105', 'b3f80a3', 
  '966f266', '57261ac', '1b7ed67', '0a6bbf9', '6be47ee', '2fe5a55', 
  '36621b7', '88f6ff5', '170445f', '550387f', '0297770', 'd2b6bf9', 
  '41a822c', '8ab4af9', '4fe1326', '4438fc1', '2a730d5', '62aed78', 
  '1447d44', '3b5de11', '65fad0a', 'b5eb495', 'e274c8b', '1d021db', 
  '63199df', '7739ffd', '4f35f7f', '490c517', '7912bbe', 'f5ec9f2', 
  'ad7d040', '3630a36', '3263f25', '3e565a9', '30b3f29', '3def846', 
  'cc1561a', '6e9de08', '13f60bf', '9703a2f', '7284bfa', '2fe163d', 
  '2031bd3', '7bf4983', '7129b9e', 'ddaaccb', 'e6ddf4a', 'f2bc74c', 
  'd623658', '37c853a', '8bf72ea', '2d11e6d', '4ed0007', '7def72c', 
  '18be3aa', 'a3a392e', 'e96cdba', '2b77729', '9be7992', 'b8d476a', 
  '1c751c4', '7dd2ac3', 'a58bba2', '7d8fa6a', '4777208', '48e8564', 
  '2efca7e', 'afe82f5', 'e84b634', '96a8b5b');

fixes['4.12']['fixed_ver']           = '4.12.4';
fixes['4.12']['fixed_ver_display']   = '4.12.4 (changeset 4e5bf7e)';
fixes['4.12']['affected_ver_regex']  = "^4\.12([^0-9]|$)";
fixes['4.12']['affected_changesets'] = make_list('b2f52a0', '22bd06c',
  '52ee570', '1f5c237', 'aac5e50', '724eebc', 'dd59be6', 'd446431', 
  '05e64a6', '2f4cfe5', '0475382', 'bd52c7e', '7dadebd', 'c6c5f9d', 
  'ea20eee', '99f2c46', 'd024fe1', 'e5f3be9', 'e318c13', 'ced413b', 
  '95d23c7', 'aa8866c', '2c39570', '5984905', '5b280a5', '955c604', 
  'cd5666c', '1df73ab', 'b406997', 'f66542f', '26764c5', 'b100d3e', 
  '17db0ba', '2e9e9e4', '652a259', 'b8737d2', '70c53ea', '4cf5929', 
  '8d26cdd', 'f1f3226', 'cce7cbd', '2525a74', 'c8b97ff', '2186c16', 
  '51e9505', '4943ea7', '3c13a87', 'd4b884b', '7da9325', 'd6d3b13', 
  '9fe89e1', 'd009b8d', '674108e', 'bfda5ae', '551d75d', '5e1bac4', 
  'f8443e8', '655190d', 'f860f42', '9f73020', 'aeebc0c', 'f1a4126', 
  'b1efedb', '4739f79', '0dbcdcc', '444b717', '544a775', 'c64ff3b', 
  '8145d38', '14f577b', '40ab019', '1dd870e', '5c15a1c', '6602544', 
  '14c9c0f', 'dee5d47', '7b2f479', '46ad884', 'eaafa72', '0e6975b', 
  '8e0c2a2', '51eca39', '7ae2afb', '5e11fd5', '34056b2', 'fd4cc0b', 
  '4f9294d', '97b7b55');

fixes['4.13']['fixed_ver']           = '4.13.4';
fixes['4.13']['fixed_ver_display']   = '4.13.4-pre (changeset 065fff7)';
fixes['4.13']['affected_ver_regex']  = "^4\.13([^0-9]|$)";
fixes['4.13']['affected_changesets'] = make_list('9c4b19c', 'a94d697',
  '3bac723', '8d8b4bd', '5b853ec', 'dd29f4f', '523f3ca', '6dda306', 
  'd1e1921', 'dd97855', '9d53da2', '331cfae', 'bdb8480', '985b3e5', 
  '4d65fe9', '9d954c8', '53e797c', '89d40f0', 'f762403', 'ebeb9ec', 
  '2357043', '18fe877', '41200e0', '0ed0cdd', 'ecb4697', 'f50fbdd', 
  '75bb9fe', '4fa8b13', '85dc71b', 'b335a53', '3cdc7b6', '32d5809', 
  '41e8d5d', '27e08cb', 'f6f7690', '1f27fc4', 'a7de760', '1540a9a', 
  '351c890', '3f3ebda', '7907ab8', 'ddb3edb', 'e39050c', '235bfe8', 
  '84bc28f', '9eece40', '2c9da5f', '5aacd07', '64752a9', '948b7c8', 
  '9bd6416', '97af34f', 'f799329', '0a3eb9b', 'd3d8a29', '83c0f6b', 
  '9e3c8b1', 'def4352', '95197d4', 'ef8b235', 'f17d848', 'fa5afbb', 
  '4d54414', '287f229', 'e289ed6', '2841329', '33049e3', '53f4ce9', 
  '8113b02', '0e711a0', '21e1ae3', '4352a49', 'e93d278', '231237c', 
  'ca06bce', '5aef2c5', '5de1558', 'e3bcd4d');

fixes['4.14']['fixed_ver']           = '4.14.3';
fixes['4.14']['fixed_ver_display']   = '4.14.3-pre (changeset 7bcd547)';
fixes['4.14']['affected_ver_regex']  = "^4\.14([^0-9]|$)";
fixes['4.14']['affected_changesets'] = make_list('0cfccfd', '76c7755',
  '74e9307', '301ea7a', 'da72547', '26b885c', 'a9d7c25', '5857059', 
  '8df03ef', '2255511', 'c439f5e', '66f5e86', 'b81187f', '29aeeda', 
  '98bcd53', '6f4c214', '9685265', 'e4c2384', '1958758', 'fe6da09', 
  '4a24451', '100b2e2', '8da1491', 'f7a9730', '61f2806', '49299c4', 
  'b46af13', 'e32e184', 'bb731fd', 'c3cc6e2', 'bb9377a', 'f6aec84', 
  '23d5e3d', '3cfccd7', '1ed3661', '645fcf8', '86c223c', '79774e0', 
  'e06d0c1', '1dae9fd', '64d93d6', '3ae25fc', '665024b', 'ecd6b17', 
  'c6ee6d4', 'b6a8c4f', '45710c0', 'ee5425c', '4b4ee05', '768138c', 
  '0ff7f9c', 'fcf98ef', '51278ce', '766b1f4', 'e5bce3a', '46ff245', 
  '2665d97', '7053c8e', '5caa690', 'b046e05', '3f85493', 'ac507e0', 
  'ebfdf0c', '9d963a7', 'b15c24a', 'f23cb47', 'c2f78b4', 'a351751');

fixes['4.15']['fixed_ver']           = '4.15.1';
fixes['4.15']['fixed_ver_display']   = '4.15.1-pre (changeset b6a2e26)';
fixes['4.15']['affected_ver_regex']  = "^4\.15([^0-9]|$)";
fixes['4.15']['affected_changesets'] = make_list('5a8b51e', 'c0832c7',
  'e58edae', '91bb9e9', '96894c1', 'b654bb2', '9e027b8', '45cf6ad', 
  'b11a694', '8c3a80b', '2a4ca6d', '9ab1714', '9bc2a68', '8a8b16c', 
  '2f6ebce', '9bfbde4', 'd40287a', '7850fe5', '9f44ed1', '27bc41d', 
  'd39756f', '711aeb1', '34d141e', '29a6cf1', '92c8b92', '1beb196', 
  '6bbdcef', 'abfbb29', 'c3cf33b', 'e0da171', 'c773053', '0f1002d', 
  '00bd594', '0e419e4', 'e3f5318', '4b60715', 'e949445', '9cb597a', 
  '6165dcf', 'da659f6', '17dca16', '99633c5', '2b23bb6', 'dba7748', 
  'e98cacf', '0e1407f', '61dea45', '429b0a5', '41f0903', '67f7989', 
  'e9709a8', '1a68249', 'e6d098e', '16d2641', '7b658fd', '6ba107c', 
  '2ba0d81', '3581714', '0b80b34', 'd8a530e', '9892901', '3556dc6', 
  '13ea8af', '77069ea', 'ec457ac', '4586e64', '796d405', '0aabeb9', 
  'a339cea', '874dac9', 'f034c96', '894636d', '12ebf0f', '35b5836', 
  '8368f21', '7044184', '0a64b18', 'eae0dfa', '89c6e84', '7c3c984', 
  '6a7e21a', 'ee2b1d6', 'edeaa04', 'cacad0c', '3e6c1b6', '78a7c3b', 
  '280d472', 'eb1f325', 'dfcce09', 'c129b5f', 'e2e80ff', '5788a7e', 
  'bb071ce', '92dd3b5', 'baa6957', 'c86d8ec', 'e72bf72');

fixes['4.16']['fixed_ver']           = '4.16';
fixes['4.16']['fixed_ver_display']   = '4.16-unstable (changeset 111469c)';
fixes['4.16']['affected_ver_regex']  = "^4\.16([^0-9]|$)";
fixes['4.16']['affected_changesets'] = make_list('5c10b96', 'c5bf129',
  '82de0a6', '0c229e6', '5f864f4', '0e719f6', '2358d99', 'd9bdfda', 
  'd4f269e', '0c58617', '1c52edf', '38c1818', '332c735', 'a4ebe12', 
  '2ff4449', '6c27a8d', '2d4978e', '5325b3e', '2107cc7', '96607a8', 
  '6b4f6a3', '305c2c3', 'daaf007', '8064488', 'afab477', 'b6da9d0', 
  'd07b7ed', '706551b', 'c5c84e9', 'c08d68c', 'ec82003', '9781b51', 
  'b1ee10b', 'f147422', '753cb68', '0bf755e', '8ea8053', '8992725', 
  'c0e19d7', 'd1bb6c9', '34750a3', 'b02c5c8', 'a931e8e', 'c7669d3', 
  '93713f4', 'b8238af', '3cfec6a', '5ffd37d', '3e1dea3', '9ee27aa', 
  '1787cc1', '5293470', '475715d', 'dd635ce', '517a90d', '6b1ca51', 
  '4c0a199', '54c9736', '3572755', 'bc141e8', '6928bc5', '274c5e7', 
  '2e5512d', 'c53aa9e', '60a9d8d', '5c34b9a', 'e241d15', '1a838bf', 
  '5a88d52', 'b8848c0', '25da945', '0f74283', '107be70', '44b9ec5', 
  '2b45ff6', '2278d2c', '0297606', '4a69273', '3be443e', 'e066ca5', 
  '604551f', 'c85610a', '3747a2b', '58ad654', '0cdb4a5', '81f2914', 
  'ce233b1', '73c932d', '57e761b', '96e5ad4', '471383d', '0be5a00', 
  '3a98c1a', '1d3250f', 'ec6e563', '93c9edb', '6a9f547', 'ff75995', 
  '79ca512', '2c7242b', 'e691741', '4ad7540', '303c857', '2d1a35f', 
  'd1b32ab', '0dbb4be', 'd276e0f', '3758894', 'cf4aa8d', '4905c2d', 
  'ea7f91d', '6de3e5f', '89d57f2', 'ab50c90', '140931a', '10cf903', 
  '8363147', 'bfcdaae', '0cbed4f', 'd4f3125', '0f435e2', 'd213e85', 
  'ed939ef', '34108a2', '484910b', 'ad76d87', '3ce2765', 'e362d32', 
  '63fdea7', '32cbc7f', 'cc83cae', 'b8d27e5', '09af2d0', '980d6ac', 
  'f17a73b', '5588ebc', '9e59d9f', 'a27976a', 'c8f8881', '918b884', 
  '4473f36', '09e2cd6', '33e4831', '44e8904', 'd468f95', '5b2a552', 
  '383b419', '5fa174c', '74d044d', '67a50e3', '3bc3be9', '217eef3', 
  '07d6dd5', 'f95b7b3', 'b175fc0', 'f004fd7', 'f8582da', '17e9157', 
  'f24ec0e', 'c636a5f', 'bb11edc', '93fe181', 'f591755', '01a2d00', 
  '8a9b949', 'e87d8f6', '190facd', '7ffbed8', '6f02d1e', 'bef64f2', 
  '6409210', '198a2bc', 'f7db924', 'a0eb197', 'e705977', '8058980', 
  '3265588', 'f3401d6', '90bafdb', 'c8be420', '54f73e6', '76a0aa9', 
  'ae8d47e', 'c0fe360', '361f1de', '3adfb50', 'a800223', '2aa9e00', 
  '65f19ed', '3ce271e', '82b1b19', 'c7691f5', 'c9b59f9', '1d95fd7', 
  '9b6d865', 'c089de0', '1997940', 'bc9f632', '1422d8d', 'b291ce7', 
  '8af4b47', 'ed464d4', '4bcf643', 'f7ad9ee', 'b672695', '3ccaa17', 
  '2cf3b4b', '5d3e4eb', '93c5f98', '6d622f3', 'fe6630d', '0c0b3a7', 
  '7c313e8', '0ff26a3', '85760c0', '4e217db', 'f3f778c', 'd5f5400', 
  '8c9ed86', '163f47c', 'f7079d7', '60d82f4', '4f18587', '93031fb', 
  'd2cad41', '2bb17a4', 'dfcffb1', '3e09045', 'f5035d4', '5151ce8', 
  '87d49ef', 'e4fee66', 'c4e4434', '8cf276c', '45f59ed', '7c893ab', 
  'df24285', 'cbfa62b', 'fd5dc41', '371347c', '0ba0663', 'dd77e85', 
  '3270a2d', '411076f', 'aad7b5c', 'd211216', '69e1472', '60fa12d', 
  'c4beefc', '89052b9', '07b0eb5', '75f13e9', '4557905', 'bf1fc18', 
  'f183854', 'bd7a29c', '7bd8989', '1a0f2fe', '5268b2d', '57f68df', 
  'e95c243', '8701f68', '683d899', '632cbaf', 'dec25a2', '8c90dbb', 
  '9fdcf85', '3670abc', '8fe2409', '722f59d', 'b509d4a', '7c110dd', 
  '3beb2ee', 'b0a5b17', '7793d19', '022da00', '3673e9b', '3092006', 
  '81acb1d', 'aa77acc', '6553815', '935abe1', '01d8442', '4b77027', 
  '5605cfd', '89aae4a', '8fc4916', 'caa9c44', '8b9890e', '3ac8835', 
  '27eb683', '71a25d0', 'd1f6296', '599bca5', 'bd1e7b4', 'aa803ba', 
  '12a963b', 'b6ecd5c', 'cb199cc', '43d4cc7', '52b91da', 'd4fb5f1', 
  '30f3445', '7e71b1e', '3f56835', '86faae5', '25e5d0c', '8eb7cc0', 
  '78e67c9', 'd55afb1', 'b80470c', '3fd8336', '8990f0e', '982c89e', 
  'fdff034', '5974702', 'c8d8a1e', '7f4276f', '64d00dd', '1b4bfa0', 
  '746d20b', 'ec9596d', '3f1b508', 'a7da84c', '244fdf0', '15a59d6', 
  '93b2558', '27a4986', '7a2b787', '472a139', '09fc903', 'e19b01c', 
  'e921931', 'b066bd1', '8cccd64', '9478ee4', '27f32db', '74a8d44', 
  'aaf61c4', '398ff47', '989cf2d', '2d09c97', '3499044', 'ec4b431', 
  'e927a3b', '48bb237', '0759264', 'd26c277', '705f7b5', '7191b80', 
  '9b9ef23', '8d012d3', '936830c', 'ab305d3', '594b263', '136234f', 
  '230a2f6', 'cb117e4', 'a4d9fbc', 'e7f062e', '1f8ee4c', '48f2a10', 
  '95aaafb', 'b8e53a8', '98e6716', '29736ea', 'de75c94', 'c79d253', 
  'a877e31', '989ec5b', '537ae41', '39e7a94', '9a5071e', '111c8c3', 
  'ec0ec16', '2c6af6c', '972ba1d', 'a76f6ea', '58850b9', '11e7f0f', 
  '1df03bc', '940f227', '95419ad', '08693c0', 'fb23e8b', '6773b1a', 
  'ab39296', '3c1c6c4', 'bea65a2', 'fc5d0c9', 'fae4f07', 'e9b4fe2', 
  'f889fa2', 'a60a72c', '4f7bfef', '4a0630e', 'b3573bb', '3acd02a', 
  '50ee4fb', '1f9d9b0', 'a50eb38', '7095953', '9c1e40f', 'ead845c', 
  '187e1e2', '4d0e3e7', '36bba12', '9d0c024', '47cb18e', 'ff2e37e', 
  '880d89f', 'b85fabd', '54febb4', '8bd9c8d', '540d911', 'fe6cbbf', 
  'e0dc9b0', 'ecf5db4', '3e701a3', 'bf6cead', '16ea779', 'd5f7d3d', 
  '62cd9f9', 'aad7aff', 'a2b4c46', '7e2fdcd', 'd87e3ff', '33a8018', 
  'dd68f2e', '4b5b083', '4215992', '1be65ec', 'f27d9db', 'd4057f3', 
  'd1657d9', 'f1a042b', '6ca022a', 'aaa3eaf', '9f6cd49', 'bcab2ac', 
  '730d0f6', '2d494f2', '192f747', '1ca901c', 'a8c532b', 'a49d108', 
  '9919270', '17eaf44', 'b5b9362', '05031fa', '8d1ca2a', 'dd22a64', 
  '97f9861', '9b47be8', '849db49', 'b3de22d', 'a24d072', 'd9b1620', 
  '0d8e20d', '4e4bcd7', '3df14c9', 'b53173e', '238168b', '2b05d42', 
  'fcb97d1', 'b3d1f52', '784d70d', '7af57ae', '3e9460e', 'd23d792', 
  '5279220', '9cc6bd4', 'ed3ea7e', '264aa18', 'a33ad60', '80714e5', 
  '23ccf53', '3ccd796', '0faa6ef', 'd1de2d0', 'de7853e', 'ab7625a', 
  '1b5d913', 'd8b05ce', '1ea7f63', '27713fa', 'be167ac', 'aff8bf9', 
  '42bbda6', '5eb6f82', '099fcfb', 'b49f8bd', 'a3621d6', 'c864eb0', 
  'b0c2213', 'd3d9889', 'c5dad82', '935d501', '7ae04e1', 'e21a6a4', 
  '11ba693', '9cd905b', 'ca68c70', '463e8e6', '23eda45', '4bd1811', 
  'b4c3d45', 'e67b981', '1f3d87c', 'f811f89', 'e113ed7', 'bed7e6c', 
  'edcfce5', '64581e5', '9689b1a', '71b0b47', '0a87e67', 'd0d1003', 
  '186b09e', 'dfcf494', '025eacc', '625faf9', '19be4d5', '51207a2', 
  '922dcba', '8b9a782', '1f03580', '91df35e', '33bc2a8', '3b36834', 
  'a98534a', '0ddaeeb', '649151e', '6645040', 'f57316a', '18a872f', 
  '6425fcf', '7ee7a37', '0435784', 'e1d96fa', '06d1f7a', '5e08586', 
  'e889809', '831f010', 'd66bf12', 'e650311', '60f0ba1', '00948dc', 
  '9617d5f', '5c3c410', 'f361797', '0dc2806', '6f59dc1', 'b0976d5', 
  '8b39f21', 'c58fbc3', 'f17acb5', '8b60b8d', '40ce418', '837d03b', 
  '9062958', 'd26a469', '9c39dba', '95e07f8', '0d597e7', '9e01997', 
  '1461285', '6008186', 'eaecd32', 'c201d30', 'cead8c0', 'e680cc4', 
  '8bfceee', 'b9005bb', 'f10c415', '439085b', '486cbda', '03bee3f', 
  '7b6d288', '4ca6217');

vcf::xen_hypervisor::check_version_and_report(app_info:app_info, fixes:fixes, severity:SECURITY_WARNING);
