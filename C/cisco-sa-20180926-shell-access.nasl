#TRUSTED 6e698e58ea3f3ae5d340db7ecc1a057fe1b40c03289eaadca4308fa3a32e8616d95f8d5270b6a0e628f0dccc59dd7e045e36dc808e8490f4291f059e8ad0f0f94f617f9bf37d61a5872ed2c2c449c084769e48c47cb67db876f2b8c19382f64c8923ea328f6e1ec21e3c243087a7522f60cf09ae045a47fd886d5833fd716eb6263f2281605b1196cfe97e78bfeaf3a1e45413456b332bfbf10c64922913ac3d26d68c274822f9ffa148507c726add1afee0393318d6031432aea0bab70e0ed7e1995ecc288b81963e6105aab9de796b6f6f7522000d3ffbf0a5c8dc639fcee79b703ff17822e4a50b4d3be1ed2ea58590a6ba609ff0438920af09482cf76edffd3198cc9bd6efaba8165d42d9c1077280df1da601e829eca6d1964df6f301a99b9801ca7305138573d4d5ef8f24cfd4259889e1f17f77662edc31f130f9ea39c47940ca8243ce9a4c5f50a8a0f036caab18bc57ddb3ffb9da59001dedd3e2cac518c76d9f1c50180535b6dfd11c83f0fe4f448c47d46432bcd72dfeb2435f237f6d28acea6d9fb875c203aa0064acfe68e4a4eb8dfe2f8565488badbe61d59f714ed22ebf37237d9affe029dd54e0eee909030b0f63a3b18f6807cc16c7a51a879fa53d3ded20272910a103c51de080526accc1429c03d218d3e8175a7663cb903199bfe86bd8081544959788d0a3e071093bbb91bdd0bf6e30933132cf38cc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123788);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2018-15371");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb79289");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-shell-access");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Shell Access Authentication Bypass (cisco-sa-20180926-shell-access)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected
by the following vulnerability:

  - An Authentication bypass in the shell access request 
    mechanism. An authenticated attacker could exploit this 
    in order to bypass authentication and gain root access 
    to the system. (CVE-2018-15371)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-shell-access
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0b2b2c9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb79289");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb79289.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

# Checking models with regex, since ccf only does explicit ver list
#
# 4000 Series Integrated Services Routers
# ASR 900 Series Aggregation Services Routers
# ASR 1000 Series Aggregation Services Routers
# Cloud Services Router 1000V Series
# Integrated Services Virtual Router
#
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if(
    model !~ "^ASR9\d{2}([^0-9]|$)" &&
    model !~ "^ASR1k" &&
    model !~ "^ASR10\d{2}([^0-9]|$)" &&
    model !~ "^ASR9\d{3}([^0-9]|$)" &&
    model !~ "^ISR4\d{3}([^0-9]|$)" &&
    model !~ "^CSR10\d{2}([^0-9]|$)" 
)
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list = make_list(
  "3.17.0S",
  "3.17.1aS",
  "3.17.1S",
  "3.17.2S ",
  "3.17.3S",
  "3.17.4S",
  "3.18.0aS",
  "3.18.0S",
  "3.18.0SP",
  "3.18.1aSP",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.1gSP",
  "3.18.1hSP",
  "3.18.1iSP",
  "3.18.1S",
  "3.18.1SP",
  "3.18.2aSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.3aSP",
  "3.18.3bSP",
  "3.18.3S",
  "3.18.3SP",
  "3.18.4S",
  "3.18.4SP",
  "3.2.0JA",
  "16.2.1",
  "16.2.2",
  "16.3.1",
  "16.3.1a",
  "16.9.1b"
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['smart_license'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb79289",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting, 
  vuln_versions:version_list
);
