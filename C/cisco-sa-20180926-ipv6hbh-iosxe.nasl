#TRUSTED 01029edca9104b27fc457db79a83a51ba8bd6dcac58e363574d5e31168daa506ed56e86d0663f89ae35c839554eec869cb8785c15e1f809bedbd498a2201e46578ae650b029052727bc0537bc63a87fbcbe9ba9ddf56941ae350ae1205e84aa8770c9c6caf0755b1b5b8f3da88782384d9c224b0c0d9370778923f5ae1e0a63b9b60f73f30d08a47f5841d1e78a3bde08b086eee7d6a8f9dd4695051ffce7c3b055a23aacae33152cb35b34fbc9a6c63749a190cd540a834a0c98e33a4a1eed61e4ac5fb02700bce8432eb22be943803144d4b3f55ce12e4fccd2e1da7b0e78e8c2792b541f94113a40ea3b9db57661f575b4ad088e3fc5bd493d62aba5c86531defa2e7053211dc56611dc7d1b3fdcafc087878daa6bffdb145a13719997d5be5c72752f5b7aeee693231986ff58a34821f93c73f6a6c86dd363fc6178f60a17b99075e9fe7ca847f798e71d947a50f058783da5a75fbddea1b961096f98e8b4570619e8d28957478f12a7a5a7a8f89ef5134e4e61efad34b313e5adad5199451641c2091cfac391ff1c24115ab37be9f26eb2c705721274c9b86ba94bc00d071ff2b35473d681f4a299cbd507b47bdd8fe447002ab9157add9184c6036f127b27e048bc4e182e2d85e319fe954a7dc8cc18f249513b059359872221de74399f572cc21a229984a63292f105c4d0f86e48963d16923d63cc0968225ea04496a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117950);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0467");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz28570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ipv6hbh");

  script_name(english:"Cisco IOS XE Software IPv6 Hop-by-Hop DoS Vulnerability (cisco-sa-20180926-ipv6hbh)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ipv6hbh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d5b700b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz28570");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuz28570.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0467");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

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
  "3.10.4S",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.0aS",
  "3.12.4S",
  "3.13.0S",
  "3.13.1S",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5S",
  "3.13.2aS",
  "3.13.0aS",
  "3.13.5aS",
  "3.13.6S",
  "3.13.7S",
  "3.13.6aS",
  "3.13.6bS",
  "3.13.7aS",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1xbS",
  "3.15.1cS",
  "3.15.2xbS",
  "3.15.3S",
  "3.15.4S",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "3.16.0S",
  "3.16.1S",
  "3.16.0aS",
  "3.16.1aS",
  "3.16.2S",
  "3.16.2aS",
  "3.16.0bS",
  "3.16.0cS",
  "3.16.3S",
  "3.16.2bS",
  "3.16.3aS",
  "3.16.4S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4gS",
  "3.16.5S",
  "3.16.4cS",
  "3.16.4dS",
  "3.16.4eS",
  "3.16.5aS",
  "3.16.5bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.3S",
  "16.2.1",
  "16.2.2",
  "3.8.0E",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.4.1",
  "16.4.2",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "3.18.0aS",
  "3.18.0S",
  "3.18.1S",
  "3.18.2S",
  "3.18.3S",
  "3.18.0SP",
  "3.18.1SP",
  "3.18.1aSP",
  "3.18.1gSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.2SP",
  "3.18.1hSP",
  "3.18.2aSP",
  "3.18.1iSP",
  "3.9.0E",
  "3.9.1E",
  "3.9.2E",
  "3.9.2bE",
  "16.9.1h"
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipv6_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuz28570",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
