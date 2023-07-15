#TRUSTED 644f9adb63099b7764ab6246283a138eb7ab1a1a57b0ac69143f832ee978c7ac684e1a924d57c692d2676ec364e16f87113a1dce806ece46f40dc683df07f6f77add8cfac9b9a35eda4b8c32164489ad158cca081c088162a979e56349d3860f1c296f79b5e3bfe901f26bab06a83c91208baeb63f39b09c347c76de8f3bd97db0b894971a0e2377df761f96b59d0e21033801ffa13d64906b5562bc28f8c70af399521c60b6f3ff1e79886312a3dde05179599e1ec0c6aa655d943d6f7631a23b3f9b99707cb783730baad1ba0f2c132bc2f9e2aba0f8c84595fad4239ee79d0968991318debb2b45a1c3ec48e1aab45295f3b8059f00918091c6bc827e3ccf0b242baa05654401b00fe65da49af83bec0bce18796ef251c23c99086a45b8865c2ec630afd445bf86fdde9937c04667a25b186f9c2915340909823cbf5d9361b0d11bfd6c6ed4e4d762ca26aef2047ba1bb4dc60a74de95f3ee73b70137f3113843bb7fc0a2b457df6bb9f252d132ffc58dd24a3c103051fe1668d8a559a732921598fca77b5487fd5c489946e59e038db28246f82b05516711c270dd93b94f51ad4e522d9f8fbf5c678262bb44cae9294db1c34116c473dbb27cf0296498697bcf19190e7a2028b649ab0be18634d3dadb50a8a7a0c4ba15be30eb3d7874c711b8159f26bdc2dfe066c9945acbaace841206225d47745b27fc40634314b87e
#TRUST-RSA-SHA256 66ebe0bf19742fd42e2d44db73c1ee17d1d4f85684acd8a4c3a525ef93deb5f30eafc5176fc4988426e9411149dde5bfb1cf4553efcb634cad28fe752fa6cab4040e3723de248afc978083011c7d35afd4932abe06cf7f9110b864e1c818ac9accb4b004a37558e858ad066fa4f170aba3332913e2d206aefd7cc0111687c17daab575858f245aa80aaf763442e06672a9c43ca74db4481754ad1233b457e101d47b725f1e463b5ff88921445ff86d018206763c74ebfa7716921e8bd39a4b2cbd254dacc26e1ea3f149f9c246c35ffb58d0daf81d53368d2bd79c22723ba776d597a16851882bd3b70d43fb2bbf200eb403fd41d83bc49e06489e3a04a3c2a58e05aeaacc537c2bf8e57238ba8957844470ab19220515dada134e6ec5670de71f5be6e5a7f785385356efbd001b531fdc0ed70a6428416b68120249e6acafbc8ec98a2bd8c3cdecbf5008aa54125be732ef8a5b53922131c7fe4f611b91aa20e39953328cbc2a6a8b108ecaf075108e8c50a6f4e3487b2a7f420a382940d84c73345c7dbd8e40150aabb3b86be72db53a3a29a49347faf7d48b2f5c4aa921cac11915c8ad95c44ca9cbcce8311f60117c2ca3b059544916f25c53e567a1ad36724911040494291a9ea9767bc600e0833625a24aee48a4e4472ed3dad2a74e9fdf422b7ebc3b2fa105d8a999fd0ea5c69e782028ac491de6391a8aec23d98791
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173249);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2023-20100");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc17898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-c9800-apjoin-dos-nXRHkt5");
  script_xref(name:"IAVA", value:"2023-A-0157");

  script_name(english:"Cisco IOS XE Software for Wireless LAN Controllers CAPWAP Join DoS (cisco-sa-c9800-apjoin-dos-nXRHkt5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the access point (AP) joining process of the Control and Provisioning of Wireless
    Access Points (CAPWAP) protocol of Cisco IOS XE Software for Wireless LAN Controllers (WLCs) could allow
    an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.
    This vulnerability is due to a logic error that occurs when certain conditions are met during the AP
    joining process. An attacker could exploit this vulnerability by adding an AP that is under their control
    to the network. The attacker then must ensure that the AP successfully joins an affected wireless
    controller under certain conditions. Additionally, the attacker would need the ability to restart a valid
    AP that was previously connected to the controller. A successful exploit could allow the attacker to cause
    the affected device to restart unexpectedly, resulting in a DoS condition. (CVE-2023-20100)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-apjoin-dos-nXRHkt5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ac2eac9");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74842
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86953f38");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc17898");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc17898");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9300|9400|9500|9800|9800-CL")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '16.6.4s',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '17.6.2',
  '17.6.3',
  '17.7.1',
  '17.8.1'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwc17898',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
