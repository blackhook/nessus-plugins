#TRUSTED 295e0d6308da7daed7ea335ce20832807829c888c1c7d3394e6f9ac9e840c07359f3585712498f7e26c0facb1878df16cba6865f24e8ace313986c8dfb42953e25e844d741d19b40a80de3beace8ffe23dcca89303ce1bc829f96337ce4818658f33a94edbeda4ae21c696571ea8b0b7365000d3a5e4df05d13ab1f96b609b41521a155ca45367d63fb35d3e385f77f8023b385c5229d1b5525840381c40b6a143d7f3f17865bca511c7cc4b18e68ed93857a75b992b4041d95bccd6663f593d400e597d9cc1fd2f0206f0b3347511b86f0b4d359877ba31e4542fa3f471ddd7e0754f2ea98d06134be0336dc3da87d2fc22fae6fd4203523e611acef923c71e9084a98639c391b4ffe7d44580c4df0924f9cb0d82d1608bba53844d040a6901cde9cafbe05d82a43ccaa2ac9c2bda6ddc266b2145dc465f173f60a8734d2c767e34b8e7525cec56c53c2e0edfe3aa60f7fb09cbd48569262929b7f8c43a7acdd2eb09131f1278a76f972e2fcc28a1e073deab1b0add49b852b2cc0d468a902f4be98ede96af3ffc6e4ddaee651ed7be24b34a0f59e56d4a27518325e4900f37bebac462c4132161a48864921b26f13d2139b4ba93a5af9cd78d35f3a3f4a042e3bfe6e3d119f2de5cfac1cdb20ee80457d4b71155fe1f1814780256232c30363a4e9fa398668fcd7fc4d08232732cd7c7003bbed36b03e0104eeeac910fb57e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117954);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-0476");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg89036");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-sip-alg");

  script_name(english:"Cisco IOS XE Software NAT SIP Application Layer Gateway DoS Vulnerability (cisco-sa-20180926-sip-alg)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-sip-alg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d523ce4b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg89036");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvg89036.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0476");

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
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1S",
  "3.15.2S",
  "3.15.1cS",
  "3.15.3S",
  "3.15.4S",
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
  "3.16.6S",
  "3.16.5aS",
  "3.16.5bS",
  "3.16.6bS",
  "3.17.0S",
  "3.17.1S",
  "3.17.2S ",
  "3.17.1aS",
  "3.17.3S",
  "3.17.4S",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.2",
  "16.3.3",
  "16.3.1a",
  "16.3.4",
  "16.3.5",
  "16.3.5b",
  "16.4.1",
  "16.4.2",
  "16.4.3",
  "16.5.1",
  "16.5.1a",
  "16.5.1b",
  "16.5.2",
  "3.18.0aS",
  "3.18.0S",
  "3.18.1S",
  "3.18.2S",
  "3.18.3S",
  "3.18.4S",
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
  "3.18.3SP",
  "3.18.4SP",
  "3.18.3aSP",
  "3.18.3bSP",
  "3.18.6SP",
  "16.6.1",
  "16.6.2",
  "16.7.1",
  "16.7.1a",
  "16.7.1b",
  "16.9.1b",
  "16.9.1h"
);

workarounds = make_list(CISCO_WORKAROUNDS['nat']);
workaround_params = {'sip_agl_disabled' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg89036",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
