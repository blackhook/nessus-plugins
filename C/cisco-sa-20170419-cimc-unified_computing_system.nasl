#TRUSTED 9e2e5cd465121330b47adcf300d7fd7cbf91df155b9f7cb0816fa302dd593dbc689d74e6ecb61919ecf7ee4a32933a8498bc680b51aa8ac7437d1c50f1cea79f50972b2292d02bbaba4ceb75243e33334af9fb0a81d64275e9ff7fa285c38ff73ab648d003c43a01cbab54d8442f5fda8dc4ae429d5cf90be1e7979716c45c1f520c5cd678ddea0c49d6a2709a052838bec99593d0c97b2e628dbb7ef255b4da7382e7310211f1a09b2b7a4c1901c2b5001778895285c67785d4217826bc5de3a1669f90e9b87df6d76089ec462eb382bc3fd4788a08e6612537298a4136e1eddaa433314b5708f6f814a71209bc2afc84d459a6673ab6ac58ed5ba83863a23c669aba3f91d2ede17b7171dabcad064f225061b22ecef813fb685e826b50080fda4eafd5f11e9b6924c289c32c2ac16b0c8e784f9f80b137b38893bd91a4931e26671399395e991d29a18763c0df70e095dafc0adf88cf77d963ec5013183130f8f6ce78e35b9d134ea3e14d542a9e0adb15dd90bf910c8ae659018d6d039e55e19edacf3650b234fc7b96ff7240d2a5002089474f61b5d9b3e78f489eacad3513fd505925bf19a577423d6b9f2797595b2a676645f81aae9cd0b41c6bda7197ca5cc6d0f2b894f4ded621b1f66474b06c6bf266d02e76eaeb091306bb854ee8bceb39da49125940691fda754acda37564686a2379f5a68b4783cd03c1803f3c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102360);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2017-6619");
  script_bugtraq_id(97925);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd14591");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-cimc");

  script_name(english:"Cisco Integrated Management Controller Privilege Escalation Vulnerability");
  script_summary(english:"Checks the Cisco Unified Computing System (Management Software) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Computing System (Management Software) is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-cimc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e294554");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd14591");

  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvd14591.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6619");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco Unified Computing System (Management Software)");

version_list = make_list(
  "1.4(1)",
  "1.4(2)",
  "1.4(3)",
  "1.4(4)",
  "1.4(5)",
  "1.4(6)",
  "1.4(7)",
  "1.4(8)",
  "1.5(1)",
  "1.5(2)",
  "1.5(3)",
  "1.5(4)",
  "1.5(5)",
  "1.5(6)",
  "1.5(7)",
  "1.5(8)",
  "1.5(9)",
  "2.0(1)",
  "2.0(2)",
  "2.0(3)",
  "2.0(4)",
  "2.0(5)",
  "2.0(6)",
  "2.0(7)",
  "2.0(8)",
  "2.0(9)",
  "2.0(10)",
  "2.0(11)",
  "2.0(12)",
  "2.0(13)",
  "3.0(1)c"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvd14591",
  'fix'      , 'See advisory'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
