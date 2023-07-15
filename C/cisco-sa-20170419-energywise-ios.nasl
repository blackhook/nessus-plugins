#TRUSTED 1eceeb6a2464b226557ba79b1c78165c39f7f3fbfdfbab508caeb1c6a69dee0e5c13f172402ffff31660de2f3c2b6f15c17cd9d2666e79f0c4310ea22c5d1e6f2f6544c1b8b576e4615c8fb5400bdb208483f077379bc33891f871c95c8c83d8a9f192ea71a55e9bb2465cd08132ff945a6e48521da7814d2cbd74590fbf25621ea2e78e3cb448f4b716aaf97ed4569865bd1e9c566fad2a7d02cb6edc4762d3a0d75b111b63e7e39e7e627a5518670e6a4afb8b0052dbe7f810a86115b05a91c8fbb6b4d7e8b1ad0bdb328aec67f88a759eb083ee731f5d2aeae69582550897fecf0499bc7991c1df2914cf516e6aea689b1950fad492e9721ca4701345c03d7405803277d8cc41319171fe8c0b03f3b487b96aa9b8d10e8446a4d8e3eacaf2146702dd96c58f2c31c44daa9a2f3bd6e0f82b22265b34b37b89c82dbbffbc5bbd8c243949d0298a8a5930cf8931c31e07e6dd665e67ae169b841b065ad96fcafb0e1d5cde46ab77c86970cb1ce414ff4f5962459468af9b5e2b2f1d9cf76cd8ddc8c705f01d22e3af6fabbb8e1d591f2dcfc59c72ad1a4a616c7d364ec3de8196f57f66454cf81a0ca69bd1bcf3b387a196c11a060f1bbac1c948bbd64be03e4e1edc0231f1d67145f706f1bd8239c6bc59bd4313d53edfb256a8da87a7901e34ecdc840a58c7edb0b028f76bc0dbd3c6f86d4e303a77977d3d7491f6966519
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99687);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2017-3860",
    "CVE-2017-3861",
    "CVE-2017-3862",
    "CVE-2017-3863"
  );
  script_bugtraq_id(97935);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut47751");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut50727");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu76493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-energywise");

  script_name(english:"Cisco IOS EnergyWise DoS (cisco-sa-20170419-energywise)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by multiple buffer overflow
conditions due to improper parsing of EnergyWise packets. An
unauthenticated, remote attacker can exploit these, by sending
specially crafted IPv4 EnergyWise packets to the device, to cause a
denial of service condition. Note that IPv6 packets cannot be used to
exploit these issues and that the EnergyWise feature is not enabled by
default on Cisco IOS devices.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d2ebdad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur29331");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut47751");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut50727");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu76493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170419-energywise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  "12.2(55)SE",
  "12.2(55)SE3",
  "12.2(55)SE2",
  "12.2(58)SE",
  "12.2(55)SE1",
  "12.2(58)SE1",
  "12.2(55)SE4",
  "12.2(58)SE2",
  "12.2(55)SE5",
  "12.2(55)SE6",
  "12.2(55)SE7",
  "12.2(55)SE8",
  "12.2(55)SE9",
  "12.2(55)SE10",
  "12.2(55)SE11",
  "12.2(55)SE12",
  "12.2(55)EX",
  "12.2(55)EX1",
  "12.2(55)EX2",
  "12.2(55)EX3",
  "12.2(58)EX",
  "12.2(55)EY",
  "12.2(58)EY",
  "12.2(58)EY1",
  "12.2(58)EY2",
  "12.2(58)EZ",
  "12.2(55)EZ",
  "12.2(60)EZ",
  "12.2(60)EZ1",
  "12.2(60)EZ2",
  "12.2(60)EZ3",
  "12.2(60)EZ4",
  "12.2(60)EZ5",
  "12.2(60)EZ6",
  "12.2(60)EZ7",
  "12.2(60)EZ8",
  "12.2(60)EZ9",
  "12.2(60)EZ10",
  "12.2(60)EZ11",
  "12.2(60)EZ13",
  "15.0(2)XO",
  "15.0(1)EY",
  "15.0(1)EY2",
  "15.1(4)M12c",
  "15.0(1)SE",
  "15.0(2)SE",
  "15.0(1)SE1",
  "15.0(1)SE2",
  "15.0(1)SE3",
  "15.0(2)SE1",
  "15.0(2)SE2",
  "15.0(2)SE3",
  "15.0(2)SE4",
  "15.0(2)SE5",
  "15.0(2)SE6",
  "15.0(2)SE7",
  "15.0(2)SE8",
  "15.0(2)SE9",
  "15.0(2a)SE9",
  "15.0(2)SE10",
  "15.0(2)SE11",
  "15.0(2)SE10a",
  "15.0(1)SY1",
  "15.0(1)SY2",
  "15.0(1)SY3",
  "15.0(1)SY4",
  "15.0(1)SY5",
  "15.0(1)SY6",
  "15.0(1)SY7",
  "15.0(1)SY8",
  "15.0(1)SY7a",
  "15.0(1)SY9",
  "15.0(1)SY10",
  "12.2(33)SXJ",
  "12.2(33)SXJ1",
  "12.2(33)SXJ2",
  "12.2(33)SXJ3",
  "12.2(33)SXJ4",
  "12.2(33)SXJ5",
  "12.2(33)SXJ6",
  "12.2(33)SXJ7",
  "12.2(33)SXJ8",
  "12.2(33)SXJ9",
  "12.2(33)SXJ10",
  "15.1(1)SG",
  "15.1(2)SG",
  "15.1(1)SG1",
  "15.1(1)SG2",
  "15.1(2)SG1",
  "15.1(2)SG2",
  "15.1(2)SG3",
  "15.1(2)SG4",
  "15.1(2)SG5",
  "15.1(2)SG6",
  "15.1(2)SG7",
  "15.1(2)SG8",
  "15.1(2)SG8a",
  "15.0(2)SG",
  "15.0(2)SG1",
  "15.0(2)SG2",
  "15.0(2)SG3",
  "15.0(2)SG4",
  "15.0(2)SG5",
  "15.0(2)SG6",
  "15.0(2)SG7",
  "15.0(2)SG8",
  "15.0(2)SG9",
  "15.0(2)SG10",
  "15.0(2)SG11",
  "15.0(2)EX",
  "15.0(2)EX1",
  "15.0(2)EX2",
  "15.0(2)EX3",
  "15.0(2)EX4",
  "15.0(2)EX5",
  "15.0(2)EX6",
  "15.0(2)EX7",
  "15.0(2)EX8",
  "15.0(2a)EX5",
  "15.0(2)EX10",
  "15.0(2)EX11",
  "15.0(2)EX13",
  "15.0(2)EX12",
  "15.1(1)SY",
  "15.1(1)SY1",
  "15.1(2)SY",
  "15.1(2)SY1",
  "15.1(2)SY2",
  "15.1(1)SY2",
  "15.1(1)SY3",
  "15.1(2)SY3",
  "15.1(1)SY4",
  "15.1(2)SY4",
  "15.1(1)SY5",
  "15.1(2)SY5",
  "15.1(2)SY4a",
  "15.1(1)SY6",
  "15.1(2)SY6",
  "15.1(2)SY7",
  "15.1(2)SY8",
  "15.1(2)SY9",
  "15.1(2)SY10",
  "15.1(2)SY11",
  "12.4(25e)JAN2",
  "15.2(1)E",
  "15.2(2)E",
  "15.2(1)E1",
  "15.2(3)E",
  "15.2(1)E2",
  "15.2(1)E3",
  "15.2(2)E1",
  "15.2(2b)E",
  "15.2(4)E",
  "15.2(3)E1",
  "15.2(2)E2",
  "15.2(2a)E1",
  "15.2(2)E3",
  "15.2(2a)E2",
  "15.2(3)E2",
  "15.2(3a)E",
  "15.2(3)E3",
  "15.2(3m)E2",
  "15.2(2)E4",
  "15.2(2)E5",
  "15.2(3m)E7",
  "15.2(2)E6",
  "15.2(3m)E8",
  "15.2(2)E5a",
  "15.2(2)E5b",
  "15.2(5a)E1",
  "15.0(2)ED",
  "15.0(2)ED1",
  "15.0(2)EZ",
  "15.2(2)SC3",
  "15.0(2)EJ",
  "15.0(2)EJ1",
  "15.0(2)EH",
  "15.2(1)SY",
  "15.2(1)SY1",
  "15.2(1)SY0a",
  "15.2(1)SY2",
  "15.2(2)SY",
  "15.2(1)SY1a",
  "15.2(2)SY1",
  "15.2(2)SY2",
  "15.2(1)SY3",
  "15.2(1)SY4",
  "15.2(2)SY3",
  "15.2(1)SY5",
  "15.2(1)SY6",
  "15.0(2)EK",
  "15.0(2)EK1",
  "15.1(3)SVG3d",
  "15.2(2)EB",
  "15.2(2)EB1",
  "15.2(2)EB2",
  "15.2(2)EA1",
  "15.2(2)EA2",
  "15.2(3)EA",
  "15.2(3)EA1",
  "15.2(4)EA",
  "15.2(2)EA3",
  "15.2(4a)EA5",
  "15.0(2)SQD",
  "15.0(2)SQD1",
  "15.0(2)SQD2",
  "15.0(2)SQD3",
  "15.0(2)SQD4",
  "15.0(2)SQD5",
  "15.0(2)SQD6",
  "15.0(2)SQD7",
  "15.0(2)SQD8",
  "15.1(3)SVI1b",
  "15.3(1)SY",
  "15.3(0)SY",
  "15.3(1)SY1",
  "15.3(1)SY2",
  "15.6(2)SP3b",
  "15.4(1)SY",
  "15.4(1)SY1",
  "15.4(1)SY2",
  "15.4(1)SY3",
  "15.4(1)SY4",
  "15.5(1)SY",
  "15.5(1)SY1",
  "15.1(3)SVM3",
  "15.1(3)SVK4b",
  "15.1(3)SVN2",
  "15.1(3)SVO1");

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['energywise'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCur29331, CSCut47751, CSCut50727, and CSCuu76493",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
