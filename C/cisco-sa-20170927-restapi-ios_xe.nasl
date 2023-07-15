#TRUSTED 325c3e2ddea62080d314b516e9caf92ced3c43d17ce67d2626b6ce6cdf93bbce7c1738281e0ca7b33e7a9c9e259be092198f7632d2bc4d53b74eb271ebf9340cc172f545ae28f27a6327987d36d903870fb93c1b485c9e4ec298f88050a2b83cacf286851a456333a77e144095d74b46345ad1c8bde8894468ccb5a484403d287f9568d0162dc9b02d4015c3231fb2c0c5bc7ac73ca1301389d6a58cd2183987d203b46c86506ff236c0eeea13415fee551889e63b6a5abe22a368466140520b0d35b7de98ea45bab8f80958aea8560e0feda0cea280b9fd79bbab02d2a970aac70d7df04a7d1a95b5fc5de09e49acde8c222a7b4b9aad4299044fac948c4d1524ac601dce98cc176f68ff38a1d99dd3ff2706c7717dc8f42baa2af8908d821ca77bcf336c367e2b888a50e10e54005ef4d520cbc1114825a6def753a420015a2e6810af0590e33464358734bafb866d077343ac05442a9d1bd563e77363405d76f952a388ad14c33368d0d98a8a181b38969e087aa7ba93cc5d49f96cac3c5d7edb3a0760c119bc13b472b2c365aed8ce6e44f4ee2ea297582f11793de20565f642ca2cd43df2dbba5ecd237124cf3b35c8f9e21c07132c3755548dd3a44cd23f0822a985fc4a7efefadbaf343e2eafc29c619c2a6d92a2ab5026911a05c44b1ddce8bdcae85a25ef06a5bce252a75a8f5ec73d6a9e9ba9fbca9ff1034bc3a5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103567);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2017-12229");
  script_bugtraq_id(101032);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz46036");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-restapi");

  script_name(english:"Cisco IOS XE Software Web UI REST API Authentication Bypass Vulnerability");
  script_summary(english:"Checks the Cisco IOS XE Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-restapi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d201c9ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz46036");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuz46036.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12229");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.1.3aS",
  "3.2.1XO",
  "3.4.7aSG",
  "3.6.5bE",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.4",
  "16.1.3a",
  "3.2.0JA",
  "16.2.1",
  "16.2.2a",
  "3.8.0EX",
  "16.3.1a",
  "16.5.1a",
  "16.5.1c",
  "3.18.3vS"
);

workarounds = make_list(CISCO_WORKAROUNDS['http|transport']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuz46036",
  'cmds'     , make_list("show running-config | include http|transport")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
