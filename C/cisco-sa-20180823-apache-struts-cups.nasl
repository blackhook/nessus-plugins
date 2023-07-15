#TRUSTED 531d8e919a578f5c402d55046279c6aa0319d64b11e6cfd1d400748c61e7c7ccaa711a8f2191f3390f64108dffec9cda1cfe6622e5965ce8740b74f709d83c9d97499c02c97b3848ad634219e609ff7acf98126943660349b42695aa34d768104c488c436c13e7667ce892766c7d106e37048ddcfba1ac2b772443e7a905b1e8a682e45817ad69bc684a2bce250dff79993839689a846ddc0e06ab184bbfc3958301fba47c2702e4bcc930e1eb90226c73a1a769e5c70c5b10a8341dac93b861d607f4713d05ce8f97544352f71f3a88dc9c2786a8e8747ac50f485c2b647276a41f88bb7c7cd340c7e3af67cd61a049cca011e3d9942ca32f0319c5fec33e651fb67d3d5f6f7859ea8414f333e21cac76fa1b4d3547ce78f376a0411eb50ef2dcbc163acce202bce2ef787f11028a173ada909c2b9bd82caddf4bb845e8159b4e4fb812ad4e8e6e24fad03496b0ac669c65e83433510c8b2b7915fa57f2f1f21d5866de373bf1fa4ecf5d5a50820a8f105b1744bd5693eda065b42bbb5486f28a0d2a94e6aa24fb12daafc9bf238b9c0add4691b0cbe3fe731b48a92d99ad9d4ffa22d31da79c776337c955cf2d58045aecf66c7250e7e147e1c6c36943213d6eea7c6c09437c8ec741e07e289ae48a2ec13c44a4b8ccf0d1b9824180479f8e787bdd465aa0346c61b3dcb6fe34ee45d7327e52b9c09a0dc5a05e7f4ed13b56
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112288);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id("CVE-2018-11776");
  script_bugtraq_id(105125);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm14049");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180823-apache-struts");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Cisco Unified Communications Manager IM & Presence Service Apache Struts RCE (CSCvm14049)");
  script_summary(english:"Checks the Cisco Unified Communications Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager IM & Presence Service is affected by a Remote
Code Execution vulnerability. Please see the included Cisco BIDs and
the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180823-apache-struts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a0e547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm14049");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvm14049.");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/UCOS/Cisco Unified Presence/version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Unified Presence");

version_list = make_list('11.0.1', '11.5.1', '12.0.1');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvm14049");

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
