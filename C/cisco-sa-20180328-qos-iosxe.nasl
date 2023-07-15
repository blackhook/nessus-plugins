#TRUSTED a3fe112b72b27501f20880aa1656e3ddc050397fad28aadc3abd47d6746f2d103b8c89f2fdf2267921a10443201ef4aa164fa2373f39a071127d40f337a43f47562d93e7fd7bebdffd244eaa0bf0a1113026db9a0e63fd9c943db3ed342a6ec0fc85db59c9b9df340217c44a61b439f18e80917324aa5f1f27b0b04ffb10db83e7e3fb508f3640aa0b1ca03af93effc85f09bd2e028e70bb2433c958507b4c75640f0977d8f9420002c800f6452735aa76328d1792d4e294ec7faf0746e201f57b73b9528d62dee016d0894b9207ff312ce2d18ea7a736685d2e0d0dcfb354ff0badf4d2452761002f19e7f10072266724cacac7b381094ca9a0c2ed3130f75520a4b71736ddac2949aea4d679ce452727080e481daee780552960645120ee6eed8c7b5917d6de6e93688f3cd2156d489496a952bffc62b5c66eda5034184aac5e07c71d6f4c0675cd23bcc7482ac2a6cb5129979976552ccfa449da127be0f7323b89a5abffdfd22f4a89f8917a5ddcfa677b4c91409b46776f9364962a4cf7ed89550f6a024b632d96af49b8a9f7b3784a0e119a80075c667da4a9f62aa68a2fd50f20bf66444173d30d4871a7cb1246f3a7b1eb9be8f92fe77cd8aa1e8965b86c6a4ad0e2655b3b9fbb7751620044b6d223733521610460a9039170643d1e9792ba5cd2212a397b7d0001391d8e1c60214b643223c720204980dbfa7bcad3
#TRUST-RSA-SHA256 1eca9577d840506e6096528ac9ea4a4a94fd31e931d7d4066eb9af218f7b2b86450319f9ba2e207fc9c44275678df4f1aa38994b1b1b80825a3d60a60211420cbe8e1c8e8f6f576dd2026b336850ae3423058f577ba579daf0dcadeee6e4ab9cbe4e9e2847548431ccf4cac432467d5fc67251bd249602d9c69ab4d1d182cad69f8057f196e13238ad0fddd903c22c805702bc10ad022259f06f1f2c7df8643ca23f4ad79566dc77b095a97ff8f8aefb7bfcfa8b566c3377b2499a5335745f09468cdb6710eb1a5cc6530f308dded96ac326eda8bd6bd1f3f1714b2468a40371e8040c284704108b8067d087c5526e59a0f4c5ae8be4f6f51bd0a4769c53e7ed982214370d2f3d4f29847079a2815e619120c29c0afa2153fca680d323b02dcab6520c5fa4672fc472bf6cac65d57ef09ca94b3f79bf4cd7046a540cc1adc2027a411443ce1822f20fa4a7955e588f165c08d9d3922e85b826a42aa0feb1b9b5b1c728df2d8b7bcffabed71d22bf15d38c34f40c20a28d4d7c755c47b39d3a94399736eccd70bfe4f29126e6d72f7faeb56c396e212f59aea40c8fc175b6e6d84578ac43c81de44ef45e938cb7eb268a80644dba4795832d8b607d05d4382a998564dd73d3fbd42c545ccb11a436bc2491dafd71558e7123b86fd47ee772a0bb8a0a26141a874c705d4b08ba07159200d3cc970e746caf5f25afef47273ce1f1
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108721);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0151");
  script_bugtraq_id(103540);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf73881");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-qos");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XE Software Quality of Service Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-qos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10160b36");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf73881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf73881.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0151");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "15.2(2)E5b",
  "15.2(5a)E1",
  "15.2(6)E0b",
  "3.14.0S",
  "3.15.0S",
  "3.14.1S",
  "3.16.0S",
  "3.14.2S",
  "3.14.3S",
  "3.15.1S",
  "3.15.2S",
  "3.16.1S",
  "3.16.1aS",
  "3.15.3S",
  "3.16.2S",
  "15.5(3)S0a",
  "3.16.3S",
  "3.14.4S",
  "15.5(2)S4",
  "15.5(3)S4",
  "3.16.5S",
  "3.16.6S",
  "15.5(3)S6a",
  "15.5(3)S6b",
  "15.5(1)T",
  "15.5(2)T",
  "15.5(1)T3",
  "15.5(2)T1",
  "15.5(2)T2",
  "15.5(2)T3",
  "15.5(2)T4",
  "15.5(1)T4",
  "15.5(3)M",
  "15.5(3)M1",
  "15.5(3)M0a",
  "15.5(3)M2",
  "15.5(3)M3",
  "15.5(3)M4",
  "15.5(3)M4a",
  "15.5(3)M5",
  "15.5(3)M6",
  "15.5(3)M6a",
  "15.5(3)SN",
  "3.17.0S",
  "3.18.0S",
  "15.6(2)S1",
  "3.17.1S",
  "3.17.2S",
  "15.6(2)S0a",
  "15.6(2)S2",
  "3.17.3S",
  "15.6(2)S3",
  "3.17.4S",
  "15.6(2)S4",
  "15.6(1)T",
  "15.6(2)T",
  "15.6(1)T0a",
  "15.6(1)T1",
  "15.6(2)T1",
  "15.6(1)T2",
  "15.6(2)T2",
  "15.6(1)T3",
  "15.6(2)T3",
  "15.3(1)SY3",
  "15.6(2)SP",
  "15.6(2)SP1",
  "15.6(2)SP2",
  "15.6(2)SP3",
  "15.6(2)SN",
  "15.3(3)JD8",
  "15.6(3)M",
  "15.6(3)M1",
  "15.6(3)M0a",
  "15.6(3)M1b",
  "15.6(3)M2",
  "15.6(3)M2a",
  "15.6(3)M3",
  "15.6(3)M3a",
  "15.3(3)JDA8",
  "15.3(3)JF2",
  "15.7(3)M",
  "15.7(3)M0a"
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_udp_dmvpn'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf73881',
  'cmds'     , make_list('show udp')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
