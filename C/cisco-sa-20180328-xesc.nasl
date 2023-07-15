#TRUSTED 3fa3f21de91f727d4c94d30e79e7d906f2a9b6096998edf4ce5c5ae2cd78a04e548e28ac814d38a856254205b38996f3f85eb51bb6c062bb9fe493957f928795e758ddc35babf553fb5962463f9109e375b5feb22d7b4392d2c0eb327dc5ee54eb592450d800d749ea6d5eb97b2c17bb163cb27061887f3c6215593729ef8788429e8ae4db4fe951254f90b3c4196f0b4fb4fa00701a5b6cec1d9b6687482743ab7460a089d533daf075b05df7ace995929e58a31e80f4063db133323a6a48fcdc9893407cfd784e17f8b67c986ac0e0abdc492927bf5907e27e533f508c7e8996419076ec422c369ce907eb7c06c0a4cc9176634aa9df7348e4a9aad0cd834907c71aacd21a1471e38d7848ab16ef7bc2109c019fdbe14fa9e8122f49b02c00a043ddf0106092ba80229f8c49e78c5355a0420f25252037f19ea21cc867d6f68fa8269dbbaa8d22f11157d9df659b69079211f5129cdf5b4bfa4cfc48ec564c9d960cca2a340cd0faca9e34eed9fbe08639e1d3755d42a4e9116bd2de9240395ff0c2c9e42a49d2e27fd3489c5ae901f753dba7030942f56b661ddbb380a2f687c130f4d385ed538d786dc082246cd45ba3369c91a6057cade0274a4ca09d6906327f2a059721efe4adc76b73dfec4128e60aa30a846d1a1de25c667f1dd421d7b27aa5972e50c43cda3be80ec31b12a63af0eba83b9d3f540491cde98d12d9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108724);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0150");
  script_bugtraq_id(103539);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve89880");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-xesc");

  script_name(english:"Cisco IOS XE Software Static Credential Vulnerability");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-xesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69286111");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve89880");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCve89880.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0150");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "16.5.1",
  "16.5.1a",
  "16.5.1b"
  );

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCve89880"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
