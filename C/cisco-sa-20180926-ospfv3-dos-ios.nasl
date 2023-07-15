#TRUSTED 15e28a5d7f4c95dd824ce30d8718ed22aef7f51e892fd6b4d1b4cbbd46911cbad33ec4c235f085907e6a76bde28000d9a35b8d384d14ba037726ff6241b0f3552a0796c96bd7a2834920803f206cce26df64a290133dacdfe961d78b6dbc6d4c4b9417d9dc52dfe3ead944b8557a37b072f89e1c7bea1441887785ab76e6c8bfd20196e62c14e4199bf0e957943cba2df6be36e5643a8a5c1e7fadf39f3f2a413bb006bd1d4f07ba741a5de3df3482212b61b95e09fe2d4bb8b608b69d55a19462a8cc459ecf772833cb7683c76e51cbdba61a6a893e0333151cf2159f8b73708418ce1558b8ed63c64b45380d106f32ffed13f9d59f6aa34183f43395436ca490f9ed93e1aa89cac2122c15405f045351ec494a9e2ca88180a067b3261b9587ce84d027fc3d3b4efa4d342997659e68b76791aa3b9ec5af1e63f89c22909a1cfc7f688124cd7e9b4428e479a5e775b14d1dd64613acb5cf07c353adf4190c922683ba1a4ed0e0e12c56685072594fa327d3e840569ba0f61798e0c847b63a30a6501e11ef54ecbd449eb75429d13e2db042ef40abc9ece8eb7a561df2ceb5e3ad90614b1ac15eee08adb78d07862482f54f3427a9840ae86ee594f9084f25c7b55782d17417252546397f76f6c39385aa30280e07f673df38796b4b361d0e7e1c3e772f5b3ad3b8ec8f2a0929a49755670044d5a0f68e4a4e4e349e4058c08a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117951);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2018-0466");
  script_bugtraq_id(105403);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy82806");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ospfv3-dos");
  script_xref(name:"IAVA", value:"2018-A-0312-S");

  script_name(english:"Cisco IOS Software OSPFv3 DoS Vulnerability (cisco-sa-20180926-ospfv3-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ospfv3-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c10abe5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy82806");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuy82806.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  "15.1(4)M12c",
  "15.1(2)SG8a",
  "15.2(3)E",
  "15.2(4)E",
  "15.2(3)E1",
  "15.2(3)E2",
  "15.2(3a)E",
  "15.2(3)E3",
  "15.2(3m)E2",
  "15.2(4)E1",
  "15.2(4)E2",
  "15.2(4m)E1",
  "15.2(3)E4",
  "15.2(5)E",
  "15.2(3m)E7",
  "15.2(4)E3",
  "15.2(5b)E",
  "15.2(4m)E3",
  "15.2(3m)E8",
  "15.2(3)E5",
  "15.2(4n)E2",
  "15.2(4o)E2",
  "15.2(4)E4",
  "15.2(4p)E1",
  "15.2(4m)E2",
  "15.2(4o)E3",
  "15.2(4q)E1",
  "15.2(4s)E1",
  "15.4(2)S",
  "15.4(3)S",
  "15.4(2)S1",
  "15.4(3)S1",
  "15.4(2)S2",
  "15.4(3)S2",
  "15.4(3)S3",
  "15.4(2)S3",
  "15.4(2)S4",
  "15.4(3)S0d",
  "15.4(3)S4",
  "15.4(3)S0e",
  "15.4(3)S5",
  "15.4(3)S0f",
  "15.4(3)S6",
  "15.4(3)S6a",
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
  "15.4(3)M",
  "15.4(3)M1",
  "15.4(3)M2",
  "15.4(3)M3",
  "15.4(3)M4",
  "15.4(3)M5",
  "15.4(3)M6",
  "15.4(3)M6a",
  "15.5(1)S",
  "15.5(2)S",
  "15.5(1)S1",
  "15.5(3)S",
  "15.5(1)S2",
  "15.5(1)S3",
  "15.5(2)S1",
  "15.5(2)S2",
  "15.5(3)S1",
  "15.5(3)S1a",
  "15.5(2)S3",
  "15.5(3)S2",
  "15.5(3)S0a",
  "15.5(3)S3",
  "15.5(1)S4",
  "15.5(2)S4",
  "15.5(1)T",
  "15.5(1)T1",
  "15.5(2)T",
  "15.5(1)T2",
  "15.5(1)T3",
  "15.5(2)T1",
  "15.5(2)T2",
  "15.5(2)T3",
  "15.5(2)T4",
  "15.5(1)T4",
  "15.2(3)EA",
  "15.2(4)EA",
  "15.2(4)EA1",
  "15.2(4)EA3",
  "15.2(5)EA",
  "15.2(4)EA4",
  "15.2(4)EA2",
  "15.2(4)EA5",
  "15.4(2)SN",
  "15.4(2)SN1",
  "15.4(3)SN1",
  "15.4(3)SN1a",
  "15.5(3)M",
  "15.5(3)M1",
  "15.5(3)M0a",
  "15.5(3)M2",
  "15.5(3)M2a",
  "15.5(3)M3",
  "15.5(1)SN",
  "15.5(1)SN1",
  "15.5(2)SN",
  "15.5(3)SN0a",
  "15.5(3)SN",
  "15.6(1)S",
  "15.6(2)S",
  "15.6(2)S1",
  "15.6(1)S1",
  "15.6(1)S2",
  "15.6(2)S2",
  "15.6(1)S3",
  "15.6(2)S3",
  "15.6(1)S4",
  "15.6(2)S4",
  "15.6(1)T",
  "15.6(2)T",
  "15.6(1)T0a",
  "15.6(1)T1",
  "15.6(2)T1",
  "15.6(1)T2",
  "15.6(2)T0a",
  "15.3(1)SY",
  "15.3(0)SY",
  "15.3(1)SY1",
  "15.3(1)SY2",
  "15.5(2)XB",
  "15.6(2)SP",
  "15.6(2)SP1",
  "15.6(2)SP2",
  "15.6(2)SP3",
  "15.6(2)SP3b",
  "15.6(1)SN",
  "15.6(1)SN1",
  "15.6(2)SN",
  "15.6(1)SN2",
  "15.6(1)SN3",
  "15.6(3)SN",
  "15.6(4)SN",
  "15.6(5)SN",
  "15.6(6)SN",
  "15.6(3)M",
  "15.6(3)M1",
  "15.6(3)M0a",
  "15.6(3)M1a",
  "15.6(3)M1b",
  "15.2(4)EC1",
  "15.2(4)EC2",
  "15.4(1)SY",
  "15.4(1)SY1",
  "15.1(3)SVK4b",
  "12.2(6)I1"
  );

workarounds = make_list(CISCO_WORKAROUNDS['ospfv3']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCuy82806",
  'cmds'     , make_list("show ospfv3")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
