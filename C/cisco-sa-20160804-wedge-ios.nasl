#TRUSTED 01f5484709fbdc9b080d3c52d26d5946f28eece4a43efae047439fa652b17cf36811e5ef766761b2ad43be7f7dad4045181e8a743df9193c7bae587a04cd3dffcd03c844e89da5ee092d9a89f3c9886d668ebe5aa548f7f270305b5388b8b8514bcead18cdf91bc4a9ee6867e2d89fbe3102cf6d49c690a6e1d17ef230513dcbfffa75fc073e2267eef856d2ae8583eed0c61382b1dbdaab42d1e48d3d0fc134cb88e7dbfdb313f5c8b2894a0bf09786b1c6bd230d5fe1f3637b05bcb7eb0cb942a92de17a4988ce76346089d056064ce1d02c780f93678cfc78fa148e8bc6ab25e855e7013c2afe6fddbe54389b054f9e5b6c8805692224ee1e6c426369303b716382e764f38e3e3c13e4718c0286bca53d6d76956b52aaa912a49479e6ee6a615627f8361c056a8877347420ab20d58516122575dfd4ef56474fe24f90e08431797e89d1c91ee5606484843e4b37b18bba7e10bbe7817fd712ef83566b1454f0cf81303d6ed88b4d780ccd30b5875055eb97ec2ea831e2591cfe867ba8106ac940b08f8329b32e12b480f300f7d6120e02b64732b8da45f6e0fda83dbb434c051977e81746600e7a0d93b17833b2500c9009a16bf760fec1b4c9faa226b953f6ed46fa9060a46c0c2026b1b0d63d3b2cba078f9313360d8f7e2c64a16632a4e8ad24179162e513c33f837761df19caa02e889995b2193cbad4fd3427137ca2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93192);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1478");
  script_bugtraq_id(92317);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva35619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160804-wedge");

  script_name(english:"Cisco IOS NTP Packet Handling Remote DoS (cisco-sa-20160804-wedge)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability due to insufficient checks on clearing invalid
Network Time Protocol (NTP) packets from the interface queue. An
unauthenticated, remote attacker can exploit this to cause an
interface wedge, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160804-wedge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57eccdac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva35619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

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
if ( ver == '15.5(3)S3' ) flag++;
if ( ver == '15.6(1)S2' ) flag++;
if ( ver == '15.6(2)S1' ) flag++;
if ( ver == '15.6(2)T1' ) flag++;

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");

  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCva35619",
    cmds     : make_list("show ntp status")
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
