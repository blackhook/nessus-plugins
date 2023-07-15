#TRUSTED a16fb2b378eddd239cf669a07470bc21876a4addd54b429fe5d24c11fc15961951dad78f2f2c8270dd47cf4677240ca082299c3baf9dab95a578b95d9eae81aaba419846ac9ff2af966528ab461a5cd54587edb6d24fa40861ea1dfa244580ebdc090f99817ad7d9536dc10fef75347a2deb525884030322a5b7c4f3ef8f24323063959d460ad33fdcc40f6dfc20fe10a3825a2eb393727dc23c381273ac63ed6419c063730cb87fcc1bc0e2d574f96f8ddc86be38c86f792cd5920c09f6674d54de6526752b8085e78847d4bfaa801f9b5ec7f5e211f5396f6333bd4760920ab3b1a75502bde9f3b2c75bfd46e676b78a6434b94e103dcf8a1745432065db4c970b39af824850b4807301386464235ab0f8d5c2d61b2194a3cd3977a6fa9d4f2d372f230e2bd232002427b2a5aebcd61a7cb44efb3dc2267c85f816a8671b2dacd0b9c78ddece82b10f6f8bb84ccca04b5ed06572ef71b1b5ddc95eb2d17dae51d0f135a1d83cc8116fd7dc8def9280becddc27017c9599bd00cee1470001ace6d93ccf228e6b74474979aff94b866961b2a064c93a9b84467084c8ae03a1a7f2962065b3705f506a1eccf0f4eb7e6133984980733512333aa1461b7d146fc2c33d673a5357bc203e735fa960b9fe7987751e2ffdad0d3a530f396e376f6599b61f5bb22efbf6f98ac8b7204db786ca59ba5aa39bc2fbce078531910e67c1b6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102363);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2017-6616");
  script_bugtraq_id(97928);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd14578");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-cimc3");

  script_name(english:"Cisco Integrated Management Controller Remote Code Execution Vulnerability");
  script_summary(english:"Checks the Cisco Unified Computing System (Management Software) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Computing System (Management Software) is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-cimc3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97646b76");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd14578");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvd14578.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6616");

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
  'bug_id'   , "CSCvd14578",
  'fix'      , 'See advisory'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
