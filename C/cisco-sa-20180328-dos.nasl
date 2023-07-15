#TRUSTED 34d25e83659b70153355084df44250cf6597c2294bfbb364a8dfbe45d2256892f68748c0312d7ae617fe660cf78e1e05192ebfb5167871b2b4af1fd3cfa06500c52f690b5cf11d94c198a8fa4ab2d076e99e9ca9f5f5a1468c4bc52512ad63d5086f4c7a3cdbacc3ae877c842032e9f2e5de25704e811fe941d64e1ab5bf3c0a74454b4bb28d5221ebd28be41300e95cae0004a8f2d6d18ec059f29ed6e0cb34e18449282877f22af97d8f58bf57f879d2dcbe9c853321cf733b2f574b19fa5b23d1c791594ae72173327015d89c828e6908a6616df9ac6093cfef56538150db0505e8d16d88c07cd40b07280f3b88391804665d2304d290dae3d266b2a6374c5f495b5e1efb8f5dff7275a0305dff6b9501903420e268b5e167d3b927ba7a1cb1c7c8f9e8811315b700d0c9ac558208c7de3e69c57f6aeb80592a85e81ab3c84fa806d141fb04723d12e4b89d4e04ecc38c86e6e404a140d7e5c221787db8ce9c3c88a588622a1bf305cc0e9966c1f68c64059d937ff6cdc4b3fe60e7318e67bf87f4e5c64531223cd8767ca9f23b29a414b87f26671ff88cc2994460b3b91913f63e5f533afe86bbd9bd80ecfac40f21d612df7726c3c03a3d4525142357b3688a1ab1882bbdeebaf2e25bccb3493ea51ab9402d029f64c90cefbac463960d6ec73a981d1350b95afb3bcff38c0d154f5dc1ed8a5cdad51fb8aa468f337dae
#TRUST-RSA-SHA256 0c9c77b24b1d92f552e02914ac430e83dec9f4e821f7eb84cfdab32c5aa6c0b7a66fcfd0a1752e0679c64ba3430443d052a120344532afd493b5c729d54c0102c9b78ab9482ce591800aa4c997210cc8d41356d700f64dad7ee8412f7799536f0202b826e2caaaad649a3c73afeb2d5025b5f61e80b570ba7ed032fd45d1aea05461f4f9327584e3d8e6f800e1aa95cf8c122553ed7227c7b7baa8a20bd329eae3c9ffc4f946a50410cb5968ca4a4d7ab8fdb31c9fbfcfdedcce2e19bcc4b6364e6afac0be3dec828121d630dc01aeff9b967cbbb95281412321a91da9ea0b4e6f5440f870dd02d79e772e1a83a2af4abd3499840a00b703f9f72824c701edc5e46f5ce33809e68b29c4b0ac328f450e8bb376e6aef66f13beb9be6156298673b2222e9e4df79477c647f3f8bcde7a634cb902a62c9ebd521345466cccac1fe06d82d12e082ea1a70ff760845f4b62059d35410958669635476690f69f1984310e6d93fd45265579a26afcde5fea00c050ec79239a7b4dd84a8603f4f9c317e0c9b4620782ebe3014c9e024c80b1f7dfd17ef6d9608850a248f42212e5769210bd7d2d958b55f6175566e90864c633e8f7055bfccc8127e46a9489894985464d6b06f9e19c0bbfec5ff9e5b605edada437193e493698467e932f04e34693fa646d1ebd114d6ee13abb2cbbe7119098d7b7b2a9c917ac1332d2d658d187ca686e
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131166);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0154");
  script_bugtraq_id(103559);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd39267");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Integrated Services Module for VPN DoS (cisco-sa-20180328-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a vulnerability in the crypto engine of the
Cisco Integrated Services Module for VPN (ISM-VPN) due to insufficient handling of VPN traffic by the affected device.
An unauthenticated, remote attacker can exploit this by sending crafted VPN traffic to an affected device in order to
cause it to hang or crash and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba6da910");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-66682");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd39267");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvd39267");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.2(4)M8',
  '15.2(4)M10',
  '15.2(4)M9',
  '15.2(4)M11',
  '15.3(3)M6',
  '15.3(3)M7',
  '15.3(3)M8',
  '15.3(3)M9',
  '15.3(3)M10',
  '15.3(3)M8a',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.5(2)T',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.5(2)T4',
  '15.5(1)T4',
  '15.5(2)XB',
  '15.6(2)SP3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['ios_show_crypto_engine']);
workaround_params = {'vpn_regex' : "ISM(\s|-)VPN"};

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd39267',
  'cmds'     , make_list('show crypto engine brief')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
