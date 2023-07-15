#TRUSTED 4d94803e2c2a146d409b92fa927318a768edaaf837381a473c86cb84c4d3fdb6d496e04bbd3519dfc29ee54885c90d81ae11f022137843bf2e2526e8af0680cae64e1edd1dc6f308700240ccaafc4706edd1bc4cc1c3e941a6d2e6608a1ea93e1006871be426d4cf0c26dd87bacad4540341deafe23971d8a3ca0f533be8c9b8da9de3cd9faf9ce9701897857031887e6b361d7d77afd0d71b09393d956766c33a2934b76704928183582afa3ff1ee6b7d59e25353b8a87d624ff3e6143771363c45344547b3f86b86ba8b06f2f6041febddd6d5491b09ff5d86844b49e961fc92bba5538f91893f76a189a7fb6e220418b3eb9bd29eadb9837b74b6150f017ebac4d7398b1fab5fa9d0794e8652548ae9330d55a0d47a8b45c47207c7736e56acabcfd06db88d699328c348ffc69d7376012ab1ad784ce35f8a7ebae4272b317413fee9e0d7909dfb454feff71a35e6b8c8c18f66006bc2a8c692fe0e582eebd6ae1fc571ee15c2f75e21d0e6b53ef5f91f6f1dc85e2681f60acacfe0723c91bf910446a5ef28668bdb6cd896f36f3cfb99eabfacc5422feb577a3f771df74fa2583052705c01d8a657d1d490b91a685251d6cf90d8e70e3d0ddd246c2bb37f20442abc1546c07903ec1ba31d644210c0b56f17b48b698ea6a47e1b61044097de07b341ba6ecd051460a627178941169d69b0a7874f154b313fb9db5228cca9
#TRUST-RSA-SHA256 1e1e2f9a307d2a7091ee9c034ecaa7ffaf4786f827f87eecb268c5c1eb561b28c4f91419c3dd68d82c95f5a389ea96e6c874ab381a0c438495256ca71a5197b5191220ee12442ea54290e68ab60490b7ff7299de9fbb04f52d077e68945c50f3b8ce7ac0515aa7610122f0b72676e995bc0198e28b27be34e6821f5eb3e696c79f3c62c3dfb53da664cdc67f514a415ed8ac159a447c7b33654c31e4a21c4388cd03cbbd46c240802338ed5c8efe1361cb4e48ec096dcb56230d7d07c79c4b28a00051d54ba875683fb0ca82543ffa5d644d3d56ac530cf05bf5e3e7aa375f73485c3cfe5a04fc0ebefc27213f3b641f680059e3a0c5e973f881c1829863ce88cb0f6a14f8101515a0a79969ee4732e448f8ea883cffe3efac4e902153a9daa6f5716246950b327e0abd52a0c6d213552b421973a0cf87601931a53f1ef2fe67fa932dae947ffdba61fa0926bcd549d91ade7371a13b0d548eb870df7f216e50fc4a0c4fd02e0446e338fbb83f6bd4269d2d89d540a3d39c528534ce0845f66610c90a5f850c57584b14ab9dff8aa0be9298e0e748c0e215debc3c19424db10eb7809236590cb8e8341de5b15d54f868f21659362b80a2d64990b6c2677abcca5c245aac95723bf586e30341e7afe39a6fe5ebffbc5918d15c1052c06c62a4bf0d6e98a80bb6445d22616f780bd66cb32c83b3c2348d40a289eb6696cf368772
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136891);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3283");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89361");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-tls-dos-4v5nmWtZ");
  script_xref(name:"IAVA", value:"2020-A-0205-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0042");

  script_name(english:"Cisco Firepower 1000 Series SSL/TLS Denial of Service Vulnerability (cisco-sa-ftd-tls-dos-4v5nmWtZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a denial of service 
  (DoS) vulnerability in its SSL/TLS handler component due to a communication error between internal functions. An 
  unauthenticated, remote attacker can exploit this issue, by sending a crafted SSL/TLS message to an affected host, 
  to cause the application to stop responding.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-tls-dos-4v5nmWtZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b40117e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73830");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq89361");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq89361");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
product_info['model'] = product_info['Model'];

# Hotfix detection not yet in place.
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

if(isnull(product_info['model']) || product_info['model'] !~ "^10[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [{'min_ver' : '6.4.0',  'fix_ver': '6.4.0.9'}];
workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['asa_ssl_tls'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq89361'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
