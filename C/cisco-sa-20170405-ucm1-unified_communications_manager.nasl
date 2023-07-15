#TRUSTED 2ac125d8b23087b539342a81a98124a1fbc43def8017c670d7cec2b6ed4e32ecc97aaf9b3f6b837606a53e93a6d6041953378e815aa1ec02d6e64563919012b0eaa5d7cb14c6f582d0cdabb56ee1faaa3aef294549484c94213359f21880cc2c71516f9e34258873c5203f573e308c5c7fe9ffc682f9f4d834eda6199e29e9b21a283cbb2b2c28f6d05940c65d37600a354123fb2f8543a90b0a500fc4f8ec0669badb8626d2e941adc36ae14b60b287bbc76fb7fc24ebd8830c1b0b8a053f8511b6f2b50e6f7e16c027decf267013e075188e311cec16430e91bcfbfec0662383372e4cde473e68df9432d35fad96579d4c7ce8b8749d09780274094a94733619fe91ecc720d42259717d9a6f9323daf17345447edcafdfe963c88c891b6331a5d2d36e5d5faffc73d699cfb97cd4b7f0f9b1e6d5bfe2c5d22df1161008549a086b1861acdd400077d5d5ee5bea816e009f247d1719f5bae629b0d6cd2220d56f2f4b4127265e7024538e752eca15ef85718b6f175df96dbd10a5090d22afcd602eaca194dd91dfbe0b2f4001a6c42afc115bf14baccd6e3eb8667c94144afadc11685b9a443bce4717b1adcff0432fd0cd41ace4d44e08209ec69260baa40c4e9771eca26ee5d4632655220c72b2a810b5b12831d88785f9a3cb6d17cc10f32f00f6594e7284d5dbdb6e4abf9ff527fface4586bc4b43a680771046d41898c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103510);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3888");
  script_bugtraq_id(97431);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc83712");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-ucm1");

  script_name(english:"Cisco Unified Communications Manager Cross-Site Scripting Vulnerability ");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager is affected by one or more vulnerabilities.
Please see the included Cisco BIDs and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ucm1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f507125c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc83712");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvc83712.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3888");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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
  "12.0.0.98000.452."
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc83712",
  'xss'      , TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
