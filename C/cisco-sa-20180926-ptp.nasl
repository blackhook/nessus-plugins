#TRUSTED 18b071355310039e1d565157a73b9f81a8f3262077305611cec4cb2aae877ec42d420eab0e56ca83a140d90d36b84c824270edb98042351b2f29236ef8977a5afbc8b0790f51061c3529804b6e5fa6a64662e00d264ca5ecbc8868d18971d5ffd0a80c7114ed1bd62ca90a75c8d2e96a54e03ff20c7c9abe1d9858c2e06e2db908e18627dff28062162f97686536152b93cf09fb0e2f39c9bb390b3fb3c3ace41c41779335957fddfb99c0aa9b6096e61cbb5c665e5d209e72b74bd42eb5c9728f0388a77fbdc8f2918143aafffd0af11b51d10525360981b0f473083c906676ff42180c89ed859f9eda4505da655ba85eae68ef09b5e807ca1e0648f33b9aebc4459dab65a17e50d5df27a5c7a174dcde701ac86578732b4e8616657754ef82c5c4487f12daf2e2fcdff74a48eb89782d6f71b81a0c91fe0499313724f86b11f5a7593f7a7dc10b46eeb83522d3b0919f2e74c246c9aa4445c43540cc2c51a41f7f5b574a1b1866b35c0332cc2a9016a2e3209f2554672310e74841b684deaecd456356d5bdb39fc7e0a4fa61a51c3044db19fa8084472dbe639930c039442092ce7fdc567bce7825f78e497b74095861d3610d148611fa1f90a84a89a19f63d89ef791d1b5beda4d56cfecfa1967d659d715562b379d8274692ad00419dff39bccddf5bf21522920378bbdc87469dc3c94c7c129654f81c3572758b92405d6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117953);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2018-0473");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf94015");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77659");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-ptp");
  script_xref(name:"IAVA", value:"2018-A-0312-S");

  script_name(english:"Cisco IOS Software PTP DoS Vulnerability (cisco-sa-20180926-ptp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-ptp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2643cbd3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf94015");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf94015 and CSCvh77659.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0473");

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
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("lists.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");
product_info.model = get_kb_item_or_exit("Host/Cisco/IOS/Model");

vuln_models = make_list(
  "CGS-25[0-9]{2}-",
  "IE-2000-",
  "IE-2000U-",
  "IE-3000-",
  "IE-3010-",
  "IE-4000-",
  "IE-4010-",
  "IE-5000-"
);

version_list = make_list(
  "12.2(55)SE",
  "12.2(46)SE2",
  "12.2(50)SE2",
  "12.2(50)SE1",
  "12.2(50)SE5",
  "12.2(55)SE3",
  "12.2(52)SE",
  "12.2(58)SE",
  "12.2(50)SE3",
  "12.2(52)SE1",
  "12.2(46)SE1",
  "12.2(50)SE4",
  "12.2(50)SE",
  "12.2(58)SE1",
  "12.2(55)SE4",
  "12.2(58)SE2",
  "12.2(55)SE5",
  "12.2(55)SE6",
  "12.2(55)SE7",
  "12.2(55)SE9",
  "12.2(55)SE10",
  "12.2(55)SE11",
  "12.2(55)SE12",
  "12.2(53)EZ",
  "15.0(1)EY",
  "15.0(1)EY2",
  "15.0(2)EY",
  "15.0(2)EY1",
  "15.0(2)EY2",
  "15.0(2)EY3",
  "15.0(2)SE",
  "15.0(2)SE1",
  "15.0(2)SE2",
  "15.0(2)SE3",
  "15.0(2)SE4",
  "15.0(2)SE5",
  "15.0(2)SE6",
  "15.0(2)SE7",
  "15.0(2)SE8",
  "15.0(2)SE9",
  "15.0(2)SE10",
  "15.0(2)SE11",
  "15.0(2)SE10a",
  "15.0(2)EX2",
  "15.0(2)EX8",
  "15.2(2)E",
  "15.2(2)E1",
  "15.2(2b)E",
  "15.2(3)E1",
  "15.2(2)E2",
  "15.2(2)E3",
  "15.2(3)E2",
  "15.2(3)E3",
  "15.2(2)E4",
  "15.2(2)E5",
  "15.2(3)E4",
  "15.2(5)E",
  "15.2(2)E6",
  "15.2(5)E1",
  "15.2(2)E5a",
  "15.2(3)E5",
  "15.2(2)E5b",
  "15.2(5a)E1",
  "15.2(2)E7",
  "15.2(5)E2",
  "15.2(6)E",
  "15.2(5)E2b",
  "15.2(5)E2c",
  "15.2(2)E8",
  "15.2(6)E0a",
  "15.2(2)E7b",
  "15.2(6)E0c",
  "15.2(4)E8",
  "15.2(1)EY",
  "15.0(2)EH",
  "15.0(2)EK",
  "15.0(2)EK1",
  "15.2(2)EB",
  "15.2(2)EB1",
  "15.2(2)EB2",
  "15.2(2)EA",
  "15.2(2)EA2",
  "15.2(3)EA",
  "15.2(3)EA1",
  "15.2(4)EA",
  "15.2(4)EA1",
  "15.2(2)EA3",
  "15.2(4)EA3",
  "15.2(5)EA",
  "15.2(4)EA4",
  "15.2(4)EA2",
  "15.2(4)EA5",
  "15.2(4a)EA5",
  "15.2(4)EC1",
  "15.2(4)EC2",
  "15.1(3)SVK4b",
  "15.3(3)JI"
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ptp_clock'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvf94015 and CSCvh77659",
  'cmds'     , make_list("show ptp clock")
);

if (collib::contains(compare:function () {return _FCT_ANON_ARGS[0] =~ _FCT_ANON_ARGS[1];}, item:product_info.model, list:vuln_models))
  cisco::check_and_report(
    product_info:product_info, 
    workarounds:workarounds, 
    workaround_params:workaround_params, 
    reporting:reporting, vuln_versions:version_list
  );
else
  audit(AUDIT_DEVICE_NOT_VULN, product_info.model);
