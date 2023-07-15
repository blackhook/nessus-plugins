#TRUSTED 17f701118cb06d6d08f370b56ec2551182a4fa989eb757cb2a91ccb81b2c08317f27f6dd67e019e37ebf877fa0e6d6f1b25856afc3d9004ab604f74ff6375cf92e513894512fe8becccbdb9ab2ca92ece7ca5b9a33cab7f3e1de09e700b95997b3e3083ef540efda32a1de7c9794317596c56829307c4fff478fd634909f58a327dd30c4f252e4f92fa31644321b88b516f1fd675a512b09202963f86a9bed3c83a8b82c96574053411a651f0582715e2c0844d7ef56cfd098128482d41a68b888abee44d884c2e24e8e9e97cc0b4f31a56a1d0e3453f95889b3f0013bce62a25dd5ddf313e9903e56040184a7e017bdc70ea0636c5b9d51d43e1518d60bf413860791b6dd1740cb4cf2488eca8e6f4b4260a0765f4d9cc01704606261a4755619110a5905678161ac093a66dd5df704e79046408ddcb31efb6a2884991d9b7358a05bdef4b22e90d52d9d6b7cb982d4b029d788432dd0ca0a61695a5a663833eeb83ddf025deed6340cb0df2b1b2de3aa4d98d91f6e872776a0c6b92aef58e417efb12e88805f8804d82eace9d6e43d6fb9e1ccb9377cd5eb0cb0c8ba1de8c68ad1356d66ae569e1475d6824bf723a9ae8056d5872e0dca4bb2e8cff9e0a491404ba91939ebf51bee0a76a02671f664f05b1bdd33a7dca4fa0aa58e0c627f18ee6528053da72fc5a9c7478f70931da09a44460a941195aa9c2a82d855c8438e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91761);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1424");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun63132");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160616-ios");

  script_name(english:"Cisco IOS LLDP Packet Handling Remote DoS (cisco-sa-20160616-ios)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported IOS version, the remote device is
affected by a denial of service vulnerability in the Link Layer
Discovery Protocol (LLDP) packet processing code due to improper
handling of malformed LLDP packets. An unauthenticated, adjacent
attacker can exploit this, via specially crafted LLDP packets, to
crash the device, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160616-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?810513a2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCun63132.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1424");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Check for vuln version
if ( ver == '15.2(1)T1.11' ) flag++;
if ( ver == '15.2(2)TST' ) flag++;

# LLDP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show LLDP");
  if (check_cisco_result(buf))
  {
    if (
      "% LLDP is not enabled" >< buf &&
      "ACTIVE" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because LLDP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun63132' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
