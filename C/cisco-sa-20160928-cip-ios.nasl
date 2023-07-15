#TRUSTED 730aad19f20995b4e7ea3b37fcebff427ef7e43b0b63148af70a075d6014a0cd6e879f969370b102ba3642cd86166ac84db4eef5cb1b4c2083b9d97a6d6ddd64277c53293396ff672efccb04369a9ac2579c658faedd5fb653122e014df819b19b4bc7c9017d6122f5b8916e02f12e5f341a4b1f91ad636ed360e25c3f13dffae23753653911f5c924d0709bb2e4d41a42f948f9e618d406995f92ce5112e84ff75c8dda707336cc19ddcaf8be0d4b49c9d83df01e197f63bd1405296347ae0496f8f72ec40e6f9460559126af903210ad44b5acbbef5e78b33838576f677b2e3a51526e103788e8d726ab1c43fdab8b7e18527744d15458249b016e9a92a040f1ad4da5b615400779a46db80cb1309ac89cd783fe8fe3bfad03f5a43e6e665bd614ff6b84a151aa8aa0e1c380b26b92e8a6823e6f9d1f94c75c1a012347ebff89ae3a65e6a23c180564860d90bbf861bb711b27d23c669345289cb9e4290e314575c2e1a9ff06a6923bd79e9fa9988a093a751ae29da1a3d9ecf0b10f8d2a521ad9838d593b9d27d3c78e08ea3da806656ec3658be7f811d58c7e3b5ce289c73f2554b58a1d82f1fd057baa2cb91fb819244a1e3f54d85b7d0a18c075a5dae30d94bd113fe44046554ab9776c28da26a941f277990c87f235321f9fd6e9f010fc21f4ac94bdbbf84a25c0e3a44036e3c7560eb72aea351ba454320970ec755a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94252);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-6391");
  script_bugtraq_id(93197);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur69036");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-cip");

  script_name(english:"Cisco IOS Software CIP Request DoS (cisco-sa-20160928-cip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in the Common Industrial Protocol (CIP) feature
due to improper processing of unusual but valid CIP requests. An
unauthenticated, remote attacker can exploit this, via specially
crafted CIP requests, to cause the switch to stop processing traffic,
requiring a device restart to regain functionality.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-cip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce256c81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCur69036.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln_versions = make_list(
  '15.3(3)JAB',
  '15.3(3)JB75',
  '15.2(3)EA',
  '12.2(55)SE7',
  '12.2(50)SE3',
  '15.0(2)SE6',
  '15.2(2)E',
  '15.3(3)JNP',
  '15.3(3)JA',
  '15.3(3)JAX',
  '15.3(3)JN8',
  '15.0(2)SE5',
  '15.3(3)JA5',
  '12.2(55)SE6',
  '15.3(3)JBB6',
  '12.2(46)SE',
  '12.2(50)SE2',
  '15.3(3)JB',
  '15.3(3)JBB6a',
  '12.2(50)SE',
  '15.3(3)JNC',
  '15.3(3)JN4',
  '15.3(3)JBB2',
  '15.2(2)E1',
  '12.2(55)SE',
  '15.0(2)SE',
  '12.2(44)EX1',
  '15.3(3)JA9',
  '15.3(3)JA1',
  '15.0(2)SE1',
  '15.2(1)EY',
  '15.3(3)JN7',
  '15.3(3)JBB1',
  '15.0(1)EY',
  '15.3(3)JA8',
  '12.2(50)SE4',
  '15.0(2)EB',
  '15.3(3)JA7',
  '12.2(55)SE3',
  '15.3(3)JBB4',
  '15.3(3)JA1n',
  '15.3(3)JNC1',
  '15.0(2)SE9',
  '12.2(46)SE2',
  '15.3(3)JA77',
  '15.0(2)SE4',
  '12.2(55)SE4',
  '15.3(3)JNP1',
  '15.0(2)EY1',
  '15.2(2)E4',
  '15.3(3)JC',
  '15.3(3)JBB8',
  '12.2(44)EX',
  '15.0(2)EY2',
  '15.0(2)SE2',
  '15.0(2)SE7',
  '15.3(3)JA4',
  '15.3(3)JAX1',
  '15.2(2)E2',
  '15.0(1)EY2',
  '12.2(55)SE5',
  '12.2(50)SE5',
  '15.3(3)JAX2',
  '15.0(1)EY1',
  '15.3(3)JBB5',
  '15.3(3)JA1m',
  '15.3(3)JNB1',
  '15.0(2)SE3',
  '15.3(3)JBB',
  '15.0(2)EY',
  '15.3(3)JNB',
  '15.3(3)JNB2',
  '15.3(3)JN3',
  '12.2(50)SE1',
  '15.0(2)EY3',
  '12.2(55)SE9',
  '12.2(55)SE10',
  '12.2(58)SE2',
  '15.3(3)JAA',
  '15.3(3)JNB3',
  '12.2(46)SE1',
  '12.2(52)SE',
  '12.2(55)SE8',
  '15.3(3)JBB50',
  '12.2(52)SE1'
);

# Check for vuln version
foreach version (vuln_versions)
{
  if (version == ver)
  {
    flag++;
    break;
  }
}

# Check that cip is enabled                                           
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*cip enable", string:buf))
      flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCur69036',
    cmds     : make_list('show running-config', 'show running-config')
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
