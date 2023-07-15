#TRUSTED 0d885c35ccd20c8b3d3d68bd46d901e6ad6ca1158527f3b240967b7d5c48a2cd0c3fd8abc1b4a40ede6077eab2ae6f1448fd8e138e43903f8d16eb1ccd9814a04a1a19455baed6d23a0378f33f0a70188889422fa70a4d9983195077c5333be9578cd53c0ab810b7cf5dbfd0dcb0af0cb47bbc6058d41b02a2143d575823c0fd52e77534f14a508c2eb4668a51bd7ba13f8dfde97c4005b8637085270edda5e979aacbd28f0fc109b7629119faad83616bf643a775f391a5a0ce3f28821d0f8e3746690fe14dcd6cc87bf8419c26e2c7ff6c42b51a1c72548dc2775a78841ab17a3c171aeed15fec4d5faef98a5d871ff5011469bc87546d7167f8cd3eae6cf2f639d9070966fd0667277bc2657044c9c573264cd7c02eadc991e44b828a0031bf04bc70d036907057d45f837f198d3c81459be5940bb3ae0e7504d3939e59d66286fa650e84860ff05b9787bc386f6a23a9eb68edb38ca88f2355f143b9de6fbbdbb933c103db1f271e1bcc300d0f0076f0b427eda049ded758d9c843f47ba842b297deaa0d25c0533461b56ad2d3b72d7b1613d0cfba4d78d4ebd699067dafb68b5e6bbe4e534b9945fe8e322fdecf21189233e1cbd738b737b939ff60635d377ac3bca5f24a53f066542edb71dd216d3d83bc07cb878fdac6bed1aaad3d6f2da66ed47a332eee896d7ea08dcfe1a41bfa74b475a462c5b0434acb494ee735
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141368);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3492");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr55382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for Catalyst 9800 Series DoS (cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a DoS vulnerability in the Flexible
NetFlow Version 9 packet processor due to insufficient validation of certain parameters in a Flexible NetFlow Version
9 record. An unauthenticated, remote attacker could cause a DoS condition on an affected device. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f624c003");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr55382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr55382");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = tolower(product_info.model);

if (model !~ "^(c)?98\d\d($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1t'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr55382',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
