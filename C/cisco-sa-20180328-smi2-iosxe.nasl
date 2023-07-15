#TRUSTED 3e1f70c3cc5e1b18886e2d18b18e3040b7b3d119064786a9a7aa0018d93220920b7175c529aa07db115bc9641becd7e16e45f60abe4cac8e7a424d759c297b07880f15a9ff951febb2ec558e9c783c104f0476db5769f567a76872ec4d704ffe73acdc4027f783ba18fea8222c762eef407307d6c50d9efbfc58eb43b286ce58cd9c559819206ab68451c75a17be632c767b625ae5af0b4e5e6eb9c4ed40fd391ca0a09ca2ce7cef4fb4d34da2e2241c69d6a8cfec2329759c1d0d5fd357a42bc42b53d3cf192ad3646718dc16524ef29dd34c352035e62cb5da8b00e5ed725916a1535a47f8df69859a20bddc844fba9d74788b59745b49cc4c6d641c45113c910e7133e501280c0c1ebe3d47b8efb3830bf01891924ad1f65541be1f7910ac2e1ff83c6100d58ea6ff63950a98182bedb10f2032a98869744bf47fbf736bb9fc7a28d0de6c0942978592a028962985ee45284cdd270568a9553a0eb0dc06dd86a4be0103a28c0defc09738b05a6aefc19ef82a41484ca666964d9e869564fd029d571f7d486cb103a7e021b8a99909cb49997f9029ed149cc6a11e7298b7dbbc25aabfd190a9203aca384c589a4e499e73a9c7e0a187d25fc3c3653b2c6fdeb455979cde85a985228c50463a23d76dea3116b0fed8beb068844d145d8d9c043719b748521d1ae14e59465ba91d10ac8aa28bb4955ad6d7702c700eeaa86f05
#TRUST-RSA-SHA256 0e32d2d6465c0fe30bd1c1cba19549c5cd870d7359c66cf53f0ed8be71f3e4e1d1847ee93db1f1405119917c3d4c0199687cb9102d25ef434d8fafea2daefca6244943b4a6a83e04caa1468fbd9382278b50466b876752cc190121b88f94e1fd0f66415860293c7cee44c223d44982a4b6472795f43308be39bdd67850107e93d890fcfc42649f7db70e7fd751337b13f696e7d53592acad18cefc38a37fbd46f2c250730ee4f6430c7bc75dac2202c6619c4b3b5870383b417eeaf4382dacfd72206679462b43230dbe019a536905aeb0fe0f453c1279672c7ea07e5525ae208a511feaec7e416c963a6faa27af40ec364ee3ffc78b560c816a8fd6aa876ac547c6b984d4aa2dd2cb64895fada805f1b59f26df97f9ff56f3fa42971641bc44ee4e5183427a71870eddfa99882623b988c3dcddcd09a37734926bd003b110e1388b6f0659215921598906ff1ef1ea44ea70b12430cade65a57dc3051244c929c9b5851b8af7cdada36109f5d6f3ff51a7bfad639901a81c0504bd81c9682245c840a3bee381f732c33bd76f6d49e01df12fa15c7ead9f17ed3b67bd3c1322f159578c2d993c0eebe4da3ca216e276e67e7bd119bfaf021cb1ff032872aed5672e3bae1572e59900702fb45979624ff0e243f34ebab0ac28c2926b393c2c80f9abc5adbe736515811a059888fef6a3046efd0acdd9cf719e71d844ba43e43976
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108723);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0171");
  script_bugtraq_id(103538);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg76186");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-smi2");
  script_xref(name:"IAVA", value:"2018-A-0097-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Cisco IOS XE Software Smart Install Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09597efb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg76186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg76186.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0171");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  "3.2.0SE",
  "3.2.1SE",
  "3.2.2SE",
  "3.2.3SE",
  "3.3.0SE",
  "3.3.1SE",
  "3.3.2SE",
  "3.3.3SE",
  "3.3.4SE",
  "3.3.5SE",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7SG",
  "3.4.8SG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.1E",
  "3.6.0aE",
  "3.6.0bE",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.6E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.7E",
  "3.6.7aE",
  "3.6.7bE",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "3.2.0JA",
  "16.2.1",
  "16.2.2",
  "3.8.0E",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "3.8.5E",
  "3.8.5aE",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.4.1",
  "16.5.1",
  "16.5.1a",
  "3.9.0E",
  "3.9.1E",
  "3.9.2E",
  "3.9.2bE",
  "16.6.1",
  "3.10.0E",
  "3.10.0cE"
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg76186",
  'cmds'     , make_list("show vstack config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
