#TRUSTED 631b9127d79a83cd7639abee78323f21fb9bf56c93fd9f5ea9995f6bf628403b425e080e0b3dd08bd774bf5516784a5a02ce9eddccf8f73ba37ba7cfa017a9387835107879cdc00caa57d9a5af5bc57f0b23058bde921a715c1e18da0e947f38cf2870417bd8b76e43c27aca3f65c54f8f0ed3690aa8b72ab92dd4d4e93a3256439fef39b79e15b174f9d7eb0c0b0ef43d830d0d0d1f6e4854c3168afcf8c9f44261d045607f899ced728ba4d89293c77c4339d73848c3633d61795d04247d66199f01051f9972cba52aedb0746cf4d4014870f7e6fee669c1aed1836b4fbf1070563ab66b2e52a47020cc8091039bfa454b84ea46b0e2471bf466973b2e8e6c02fa0a37624da06385461fc1af75c90cae7a76fd8d3e5d353d7e3b87733c7ec360c08a2aa5d455d8612fb078cc3dd9a4a3466d0cf18c632312ee63b1efb76376fcd01fd2e10668479cd4c1db9a3e66a35b1f90e75e01ad6af59ce480c00da5770dbafeb5a4198bf453ca736c343fc992f72ebfa81f11dec2c48298dde46eb35499fb09dfdee1a92a3c5cb74eb414722116fce9199feca0d3e7bb8df6a07e4a3137d5fcdef66dca3939951406a259cb3167ba2c7373fa1105aadf6f1f9291845a7db8661acd50e5f39574198a5fe498f0d4e7ec7cfa2d036f2ba5ffc93d67f2685c499d4433b65f0262239a5f0f07b0b1d6aed412fb4f4bc71b557c462bc9739b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82584);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2015-0635", "CVE-2015-0636", "CVE-2015-0637");
  script_bugtraq_id(73339, 73341, 73343);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ani");

  script_name(english:"Cisco IOS Autonomic Networking Infrastructure Multiple Vulnerabilities (cisco-sa-20150325-ani)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by the following vulnerabilities in
the Autonomic Networking Infrastructure (ANI) :

  - A flaw exists in the ANI implementation due to failing
    to properly validate Autonomic Networking (AN) response
    messages. An unauthenticated, remote attacker, using
    crafted AN messages, can boot the device into an
    untrusted automatic domain, thus gaining limited control
    of the AN node and disrupting access to legitimate
    domains, resulting in a denial of service.
    (CVE-2015-0635)

  - A denial of service vulnerability exists in the ANI due
    to improperly handling AN messages that can reset the
    finite state machine. An unauthenticated, remote
    attacker, using a specially crafted AN message, can
    spoof an existing AN node, allowing disruption of access
    to the automatic domain. (CVE-2015-0636)

  - A denial of service vulnerability exists in the ANI due
    to improperly validating received AN messages. An
    unauthenticated, remote attacker, using crafted AN
    messages spoofing the device, can cause the device to
    reload. (CVE-2015-0637)

Note that these issues only affect devices with ANI enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabca9f4");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37811");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37812");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37813");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

model = get_kb_item_or_exit("Host/Cisco/IOS/Model");

if (
  model !~ '^ASR90(1S?|3)$' &&
  model !~ '^ME-3(600X?|800)-'
) audit(AUDIT_HOST_NOT, 'affected');

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '12.2(33)IRD1' ) flag++;
if ( ver == '12.2(33)IRE3' ) flag++;
if ( ver == '12.2(33)SXI4b' ) flag++;
if ( ver == '12.2(44)SQ1' ) flag++;
if ( ver == '12.4(25e)JAM1' ) flag++;
if ( ver == '12.4(25e)JAP1m' ) flag++;
if ( ver == '12.4(25e)JAZ1' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.2(1)EX' ) flag++;
if ( ver == '15.2(2)JB1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)JA1n' ) flag++;
if ( ver == '15.3(3)JAB1' ) flag++;
if ( ver == '15.3(3)JN' ) flag++;
if ( ver == '15.3(3)JNB' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S2a' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(2)SN' ) flag++;
if ( ver == '15.4(2)SN1' ) flag++;
if ( ver == '15.4(3)SN1' ) flag++;

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
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
      '\n  Cisco bug ID      : CSCup62191, CSCup62293, and CSCup62315' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
