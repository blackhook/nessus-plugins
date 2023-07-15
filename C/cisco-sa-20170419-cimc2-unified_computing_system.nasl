#TRUSTED 6435c4fb05cd7b46887ad37d72bdb57f1b6067f4bd362c951ecd58a14a198356b6310f9523345c48fb9d4d129f51b16a12bec66bdea5bdfa97a2e4676c7017aba4040f54a47842b3df641ed7ef00de302aede3a11284c49a8d3347ab5da436b9afb1894d02687e5c39bcd3d1ec69d476979ed50c4fc80035297328796ad31b04e1366eb57648c06e8bd377645e2591c2df8882c3310e39364c52170ec4e2216c10dd01982ca6c8ec06e18c4ff4f3698d46e4b2034d57097f2dee408e500eaad1304ea00c2a9ae33b1317cb493add9dd961298161b09fb5b5a4dea15b3b3750b2826f4e882f106eca615372f4d1c15af5f2a68d393b3a60f7d06d56f23f9c691e7492a034a897ef069d790f5175c119de3aa6db01aa6cc6f35dee36cb67d60e6bfa7cc39623a44a0a34a3b77fd826d6306f6eb30c4d0d905303b9cf9e55ac044e693997ac053f86bf130c8c464c06f3cc14e20f2a112eed9d2dee7a842f9c32383c1b388fdc52884ae6cb4a9e6a317233ecbd494d7970b5758b2fdcf9e1a5bbf4f4f72844b9949455c669f7c101a7523cbff483c62f02398d957c5a1d3ccba3987218428a2b458fa59b2381f9e4719624c5269040269f3254f647d5f24f7694aa6d8feffd61a468128f532f6c80ed8651aba6951dcf8fdca4e67a2ee2a02a63f3d47ebbcbb06bd3e11c03d1587100a14af3cb808819bd316ccf93b1dd74ce6b66
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102362);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2017-6617");
  script_bugtraq_id(97929);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd14583");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-cimc2");

  script_name(english:"Cisco Integrated Management Controller User Session Hijacking Vulnerability");
  script_summary(english:"Checks the Cisco Unified Computing System (Management Software) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Computing System (Management Software) is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-cimc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c704912");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd14583");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvd14583.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6617");

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
  "3.0(1)c"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvd14583",
  'fix'      , 'See advisory'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
