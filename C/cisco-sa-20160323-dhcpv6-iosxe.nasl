#TRUSTED 4e346cf134fab484d2fd9b952ecd1818a51940f58e09fb66814448b7f0a2c68cdb40e782dcf170c6fa45bff3ed13aa92fb43209d33105a3aa81ad170efddd2d228e03f40d799bfb09fda74077551a307502f20ab9522e4f4e1c9227047660650f76ab608d2f409b769e168a9a891693099e3d2027465a30c6a67fab56a4f5332767f48f1564d24c8f552d23a642aae506428d92bd1ec8c4cebee85fa5035e7fae489ae29d0615b5a7c8ce0b7d766cb16ea42e4cb56d2b16ab098cbbca112c18239b441028ab7c59625fbe687a1d2afb5b92024fdaa33dbc745db66454764ddffd63036d750105aa42bd961f36021ad918314ac9c4b1ccb088e5271a1284d291f1f8b29df07702be076b350cb434d4783bd60b61150eaef95e620741171514006a8dee603655ae23d69a2826e900696fbf8c4d1752e48d04fae4591d5b3c3b8c115634a537e02805782e41b5ed83fe4c97b99eb06a14d2b440940f868d4974d93aa4aac992de8ec7dcc4a75d0dabe2b6b2806b0c08dee606c1edd3e38ecaa6ebf2de56ac7acbd24096de4e4182cf367c44bc2f71bee757349d0ebd4eadfff1bd46b474595bb58f4a9c2705bb35364ccd1116311a9708133820c59aae90e4a299365a4f9efe3dd35b0d793ac1fd89098114fbc942734329185a3c6e1021bd2eb137416aff932ab22a0fa3e5e9a4b6c0b71b8551f4d59cbc09e6d6de5e4c9480ad4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90354);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1348");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus55821");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-dhcpv6");

  script_name(english:"Cisco IOS XE DHCPv6 Relay Message Handling DoS (cisco-sa-20160323-dhcpv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv6 Relay feature due to improper validation
of DHCPv6 relay messages. An unauthenticated, remote attacker can
exploit this issue, via a crafted DHCPv6 relay message, to cause the
device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?239272f7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus55821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;

# Check DHCPv6 Relay
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    if ("is in relay mode" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus55821' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
