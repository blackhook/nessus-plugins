#TRUSTED 8122dab928a799b697c291028f246ddcc2fe1dbf0aa5e2fb7c8157899f263f65788012aecee5d43a46360d303a10b2d9f476d14c066d3a35b9a68fdbc069b7822151a9ce09232aaca8310a3c7a429f71f209283bb47cc2863351dea5b5df5140276654d6ab665638cd65fff708ce3e1ba9ad775699f1d7aa8fc7bb0f425e5ad1c593746130836143ea40f0864eb2af0a9ec1c33050550f29cde2b1970cc3ce11da96af2f87fcee69ecd4c6471ece1bb71b5970ab8b97699b758a0163b8801a58c691ceaa6f8d486ca837df145d4dd70f62ccbc5afd1f538fdc27836a0f2e4645f35922932f8c7ce005a61893156f852db390be2634b76f714cd3d1e35dcfee7b4cd6a31cdfc6b9d814ab14f46eefafc5485602106b4d609e0a198a0f93c39c5cee1b2d121078cae2e09a8da8122222605e8432e8304945a8c0e5a14be6d38b1b295a7917598d0b05ed4178477d96a4318657dff5272030ae117de53bef0e8722ec5fcdff354db8ab144bca00ac471481b6de4b2b3632d9747124c3792cdab1cac8d309a5bd892783230950b3f14292ce473e1cfb4a354e8d287d7801bd79dd0a9a14e5a8ef010db8ba7019247c5e7730682386aacdae1635d55f0c218f6e0e0c57dbad96b9add61fd6ec062b8aa0206eb0b05235d9157a8cff10a0fa431409eb89c1183785427ed9fb0de576f0e593d76f956cd03ffe7a7af769f55bd42203c0
#TRUST-RSA-SHA256 09f2a4ae4bb92da68d354cadb231ea8b35120532f044c14ad36d6c1e357f2eb02579147e40d4379f3b8a5ed60c9776623f743b5c0bd6ca3be52ff5d74d778ce8eb8481e3a22691abc4be006ca6a39e680a1994f776ae7cfbf41a62c4b7b2438556b2dda36dd1cbdc168d1460a9513a250b363a6d7285aa7d15c5053a9b3a2bddb87ec3bf6e5731a9f810fc0aa84a8e8c99c6175eb96c8713fddce4916d007ce40fc263ca606c36d83bfb902c6be73182d1324dd21ac037979a1fa0c424ddfd89572797d1730144cfa470e0586ea9102f60da4101baf37cdf4564f609df66da45ca24098383f7a03f2749ad82fdf92a5a7ebeb552ab1f5b92ea9aa1c255f93a2d62f5b7d4ce936a67f427751fe44f6c6ddf2bf76d2d73a999be50e49ea31c5d0f4c43512274fb11cb1a68deba6233b33a68146159b5cd69b1f87a977f49566fb1bf35711faed74da80d724242706e402e1ae9773c40a548728ead38fc587d10ed8688eade1ed2f79eb6638661f634d75c4d676a1adf3471697d803a1564cc38479b861013ce38c05492fee23240c69c8bca666c70df38e04d25ca2179d86c17ed61762098ec29c7bce6ff1cb6af2800d3ccf3f7a8af610d1dc2cfb0d806aa541f103e516dd356628395f2a47d9c0bcc7604cad6eb95eef2856419ad96f662ea17eed0d2008f94c291cc1c5d10486441a38ca922769c1ad20bddd15148effe2481
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136587);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3179");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq78828");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-dos-2-sS2h7aWe");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower Threat Defense Software Generic Routing Encapsulation Tunnel IPv6 Denial of Service Vulnerability (cisco-sa-ftd-dos-2-sS2h7aWe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Firepower Threat Defense (FTD) Software
running on the remote device is affected by a denial of service (DoS) vulnerability in the 
generic routing encapsulation (GRE) tunnel decapsulation feature. The vulnerability is due to a memory 
handling error when GRE over IPv6 traffic is processed. An unauthenticated attacker could exploit this 
vulnerability by sending crafted GRE over IPv6 packets with either IPv4 or IPv6 payload through an affected device. 
A successful exploit could allow the attacker to cause the device to crash, resulting in a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-dos-2-sS2h7aWe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a684b28c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73830");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq78828");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq78828");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(415);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.0.5'},
  {'min_ver' : '6.4.0', 'fix_ver' : '6.4.0.6'}
];
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq78828',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
