#TRUSTED 08fa45110a5ebaf0aff326fa0934222bc335fc41e58f9eedb006e164fff3f93ba6cdb6a4af41c7a015599076b2ced6fab7460c6d618334038bed194cb88b7d5dbb20f14282682f9c0450181f9014ce1e38a108dbf00db79c473453debf1f80740d26f133924aecf31d5afcfb9b0c68e6ca350f3f85d13bf01cd5fd67e1b38250e0f3c1f9109fbeb488ef6ef82ec4ba69c074f1e76e2304b1974e236d4e70b9143722caa5b2939cf1acaa374ec481ef106826d60b2f494e730ca5fb1f1eed930d7d0b080f659abd281e6c0a4ac70679647a609cbbfde1ed084d7c7788f1878db6c650ff4705aef05add702d04cc9ddf54a2f1c864a7e4f555db6e1c132d6c85e5c589a074d4416f4f448210afede38ed6dbc815800a51dba152cee918d32c0a2e55534dffce1d7f75564ec56adb5c0ecc5bd7e5f9e58b66446b699ff3b92c3ed9835d212c7001eddd3e1eb3b94a2e83142e95c8397845de981db1b06797b2988e29cd18697405715841c1b6eb7de4bcdab8f588339dcf8302d5ee4e0f8546ee7b0adeabbd8c75540daf3811de5e4dbc0e93b5f857be7b8f47cb48da979861f249140e562f823ccb76df7e36bb12a179aaca24e627e8d005bca6a58e3a46d275418138c7ac107e6e3a3c23bfac96bacaa881feea13781e4404f33474be073e27ac2d79d22a19558e12e892e1bb1b08ce86f9edc87833d769a566ef5cd33452f44c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104718);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-12302");
  script_bugtraq_id(101853);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf36682");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171115-ucm");

  script_name(english:"Cisco Unified Communications Manager SQL Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Communications Manager is affected
by a SQL injection vulnerability. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171115-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35ffd99e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf36682");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf36682.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

version_list = make_list(
  "10.5.2.10000.5",
  "11.0.1.10000.10",
  "11.5.1.10000.6",
  "12.0.1.10000.10"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , "CSCvf36682",
  'sqli'     , TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
