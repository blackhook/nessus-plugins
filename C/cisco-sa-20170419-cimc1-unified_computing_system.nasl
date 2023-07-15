#TRUSTED 1904f7e913fe0e55ae2e42619fa67d54f031cb7f156167d58607c1a5c94edb178e28b0f558bc7a4a4f9892ea287f6ac5c82b74865ecb833d75face15a4475f949cc4bfae866cad8a3fbea00f57ffa67dcc5002b4d97b621cdddc30c7da22f139260dd54902a21597db9ac7d132b51967182fe80bbc5156294d52839543d097bfd1ac3bd5ada04b1177391154c3bba0d804d8541b1a63701c7d91352feace070650a9b65d550ddb1f5680a099321e21c7b30c16f07c033e73d2e61649eb36f63d908bb4d2b5d9678739e78779c1ccb981806e8781967cec9f6ed6dc96fd668ff76d8da5b5df0d2cda7b80b34b1e2d9ddc0a8c34b8bce3ccc82fd675efb816b38eef51fcde25ce195a74bc0a6fbd95fee13b7643034324c6429a7980b11c57558d7cedac11a2ba617c43af502d2869354fa6fb7507f26f580e311a0cbb1922d0f18a7de0ab6570f59a066b6e8ddd033d2f27cfd8e9b41af20715960875f3ddcd91ba1f37a59465cae1563e3eb66e65b775b4b505295fd9ce687cc467a2a1e6501b8dcfc03688a4a7ba58490820b47fbcd89a068187e7881ba41965bc9f374b3982f0a86780566f7730b12f1cb95c6fd2052e923a6c4d9d2000d290869ff51f80ad2450171f30dbaf74ef96bdb0ae75c5e44fc39c127d0cc11c3ac613ffcdc6d72985cb1c1a66cd38f88bf45197c80896805029fcb0cc19ee2da3ffc887ae29e4c7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102361);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2017-6618");
  script_bugtraq_id(97927);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd14587");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-cimc1");

  script_name(english:"Cisco Integrated Management Controller Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Unified Computing System (Management Software) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Computing System (Management Software) is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-cimc1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5dae5e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd14587");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvd14587.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6618");

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
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvd14587",
  'fix'      , 'See advisory'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
