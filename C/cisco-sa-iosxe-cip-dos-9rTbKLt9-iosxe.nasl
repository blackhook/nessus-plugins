#TRUSTED 5bd6de5f9a894f55d3a2cedafe8b399ca4925f0c85a4f63d7734c990eadd332ff8c2723c9e6579ddc8618b23dce432f58ac4063660f12596fc1b215b8a0c80befe7fc9d2c62848adb6eb2f153ffd611209e007fc5b30942b5b005f2b91b77ebba2a09674b9ac6cf5bf8a173fe7abc8cb692d728621f66e62c85eb09cf41909b5aa32d84c391a6fe157722de1e27471b251670cb60987a979849d015e570a34cc09d00834e4fc3192c6ad488347b7cfc1d3101d064113008748fa8d33b945295da2c86b22b96c76b7f4e4bf8c17a35a0147414ef320e1cbf996a7fb4896156fe85f257379c0d44a705840544ccd828d2d82b2ed0e81be1be9191e955b4be19f82f315a54c133a060685853f571431bf108349a95b787a54a340675f025374015ad0b3dffdbcf4a3b0003a58b23f9d647492c4af1e801d93604b59fc3b03ffbd55c5b405d404d33ba6471eff68f963d90bd9928d74e42b2b2e9c1426605e37f0f9e136cff6f52e08504671dff2624c8d882f22c2397cd3be43e905f25643f3cc0de1718e1502aa9795b540aec6d07e871da1e276bd35df9c11463a901b9bf01f0ddc2462b6ee675f841e3e8a3ebde95ff52bf1adcc8431be2ed7be5b27880b3cf87d00aec31ae4d5e25f6648d8729dc30d1619e9b6cbc39e3f3deadae65dd04e1b0d918259d39127b92b974e4e00441db0a14bae359532cc916c9bb7094df7cb73
#TRUST-RSA-SHA256 50076600fbccc9e4ee853a76b46cfed8f67ad47e25d75ff6f9b85644b55f9b12938669232011742f46b99a6d538f2d8cb3e19fff2159ed5985747705dd17ef826589dd59fe10f8d4a18ef31209aca33b35188a5e62f3f64a93963d0d8488fc974da6e457635af101ff239e2e9b28d35f4210ffb60e965d9fddd8fa67f412e4fb928c8014423848e7bcfdcbf18efd69b40624f56b7c365921a3d6c94277e91e528269612d1ca9aa77116e63678d02f639ddd2f3e7a8fea55deffafcaa6f279caefbe34a3b3cce2da8e31e4b38c5795d4471dc9c44e73f9ce58ad97bc0e311bcb489477ee0b1c715b2c757df28d61f69f69140b14e1c2050bff62725c909bb32ace35b7a6c826bfc26c7b68236dd4af2da382df3d759d2646e8ea2bed7759aff64f31906dfdaa703cfacc53321475a0674e70ced0ed93bf541ecf46507d6f7631d6002c41136920c60b7194402e80587478956a976462e2363130adb56f9e3d8a8733ab3328790b3af8cee9c529bf7ad0dcc720cd260f1b02fff523fff02d74bbb4111b6ad78b5b1e9737727bb34dc494bc8f500417c4a7b3e501623b3aff79f46f600020beed7b0de5718c334c9c8713976c4f69ab5b1b53cab2f3ce24bcf63f44db6aed1ffb1478761e0a99e79c67d002954245ec0c89b78d1954182c3605a93b3f6a7e83b77af582ec8fa7173bad4dcfd581b5daae247f688dd6c484a0617f2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165677);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20919");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa96810");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-cip-dos-9rTbKLt9");

  script_name(english:"Cisco IOS XE Software Common Industrial Protocol Request DoS (cisco-sa-iosxe-cip-dos-9rTbKLt9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the processing of malformed Common Industrial Protocol (CIP) packets that are sent to Cisco IOS 
Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to 
unexpectedly reload, resulting in a denial of service (DoS) condition. This vulnerability is due to insufficient input 
validation during processing of CIP packets. An attacker could exploit this vulnerability by sending a malformed CIP 
packet to an affected device. A successful exploit could allow the attacker to cause the affected device to 
unexpectedly reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cip-dos-9rTbKLt9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e302623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa96810");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa96810");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(248);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '16.9.1',
  '16.9.1d',
  '16.10.1',
  '16.10.1e',
  '16.11.1',
  '16.11.1a',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.5',
  '16.12.6',
  '16.12.7',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.5',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '17.6.2',
  '17.6.3',
  '17.7.1',
  '17.8.1',
  '17.8.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['cip_enabled']);

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa96810',
  'cmds'    , make_list('show cip status', 'show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
