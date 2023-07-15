#TRUSTED 5538e58acd3b9c3603d69886501b4d03206d911e89a8d42c5b4e7eca707c4d625bc7498ef348a9ccbcb5336c36a12a8c522e9b7208a928417ca393d93d9b75b3674b5020a3adf4e9ded633106ddd86864d79657cbdb95644342b2f275592d8f9e6fc1f66ff78f01c1325c212b34be69ad9e19e9079abea97ba850b3de2a5b4c17ea6bcb025e35351d747f7a3bfd9a692abe32cfb1acd6df9a1ed4437cef173f52741ba940ea420a6a307c28113c77d3911f694bbd8b4770b2e393e952b7721160a3ace2b9a105b946878666ddb6b6277e8dd37cc0b540d3cab9ba05675333685d3567dc787a898345d49807afa2c4e8dadc80157671c59645ec28d4d731254f700afcdde8541b7fc40f5bf22104a815dfb9ffec8005793c65a930bc671999876981b110d057967ac4aec3e59486c42d91bfdbacd15266c2227ee145c9c1f68b594923b7c279533429a89c5a243111afa033972ae83c9fc79e2601de851679ed9c299cb484ffd80c57ac3b34925bb3cba116fcda0316d36ecd2faa6315da0eb4e36614b14339a5b4a8bf1733e633b7f9f29f76f24eb6dbba11d66280d6e3e0195481f24ff5256f30dbac9ca2fbd0297cc6cc377e602403cf222d850e159cf5a4a46f673c55f9ece04e1b4703056a271d88239f32fd0101e729543bc9b902ffe81653218ce1f59a8de7edc84c8cd3a6afeafbbf24ba8b4385bcd815cde5a4733f9
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112289);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-11776");
  script_bugtraq_id(105125);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14042");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180823-apache-struts");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Cisco Unified Communication Manager Apache Struts RCE (CSCvm14042)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager (CUCM) running on the remote device is affected
by a remote code execution vulnerability. Please see the included
Cisco BID and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180823-apache-struts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a0e547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14042");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm14042.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11776");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts 2 Multiple Tags Result Namespace Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 Namespace Redirect OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Unified Communications Manager");

version_list = make_list(
  '11.0.1.10000.10',
  '11.5.1.10000.6',
  '12.0.1.10000.10',
  '12.5.0.98000.981');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'bug_id'   , "CSCvm14042");

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
