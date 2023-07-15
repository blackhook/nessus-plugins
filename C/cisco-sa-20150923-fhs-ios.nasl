#TRUSTED 354df3a268d0009f526ff8eb6ab2e52e9c8882ae64aae1003cad76e280d844ae88a6568fe8a2dfca4c68fbaddb08b774176d3c7d32e7f07c136a793aa87035833a6d5b5ed564303774517f21b8fb6506449a61f5df943526c01ab9967311226df0d0634ead3d3a785ec5db0c2a9c926831ddfabb4d4c3493888701294e7e584a933fe849c59478f5c8de6604931da14f75d6aee27ed806dc51e636d751cd1f9ead29d3ff129f2ab027c432d243f4bc32a4e4ad08b2c1016ed2f17303cd80688db2e76082c6e18acdf06cacf0c97b224a867615897b27ea7a3d07ce02779a10d1be5ec561973ade234e68514f76a78cfe5889e355163270d10ef1e97704b23563b8ef83237d7396b742ea3a9b3694079907f31f74f4856cfaa2f6960311ce98aac3deefa0067890e954251b5bbd6e74169ee17260b29fb00ed8d712147d86faffadeee2eb1220f1baf60902292b4ec8bb1e9984b4473ed39a252d283022d557b6c70fdc8d52e1f32bbcc6aa781b1660bc2c0c469aa473006cfd556f6f64efc1e8d2620c3093092c91c5b9ab4e457f057f9081adabc876a80863ff262de42c93c4aef7b94fb43de3db6cbdfcfed6ac22923f047e455cd5fe4b043d007a70cb297ebae5d7c6d5d31d27bbfda4eb7b78d61cdb77ff8fe4a6791a4662f45df973f3a7297a2874e7c271c0bb2d883e00e9ad849b4c19567a3954c47c85063d3dd7209a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description){

  script_id(86246);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo04400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus19794");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-fhs");

  script_name(english:"Cisco IOS IPv6 Snooping DoS (cisco-sa-20150923-fhs)");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device missing vendor-supplied security patches,
and is configured for IPv6 snooping. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the IPv6 Snooping feature due to
    missing Control Plane Protection (CPPr) protection
    mechanisms. An unauthenticated, remote attacker can
    exploit this to cause a saturation of IPv6 ND packets,
    resulting in a reboot of the device. (CVE-2015-6278)

  - A flaw exists in the IPv6 Snooping feature due to
    improper validation of IPv6 ND packets that use the
    Cryptographically Generated Address (CGA) option. An
    unauthenticated, remote attacker can exploit this, via a
    malformed package, to cause a saturation of IPv6 ND
    packets, resulting in a device reboot. (CVE-2015-6279)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-fhs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c8077d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuo04400 and CSCus19794.

Alternatively, as a temporary workaround, disable IPv6 snooping and
SSHv2 RSA-based user authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (ver =='12.2(50)SY') flag++;
if (ver =='12.2(50)SY1') flag++;
if (ver =='12.2(50)SY2') flag++;
if (ver =='12.2(50)SY3') flag++;
if (ver =='12.2(50)SY4') flag++;
if (ver =='15.0(1)EX') flag++;
if (ver =='15.0(1)SY') flag++;
if (ver =='15.0(1)SY1') flag++;
if (ver =='15.0(1)SY2') flag++;
if (ver =='15.0(1)SY3') flag++;
if (ver =='15.0(1)SY4') flag++;
if (ver =='15.0(1)SY5') flag++;
if (ver =='15.0(1)SY6') flag++;
if (ver =='15.0(1)SY7') flag++;
if (ver =='15.0(1)SY7a') flag++;
if (ver =='15.0(1)SY8') flag++;
if (ver =='15.0(2)EA2') flag++;
if (ver =='15.0(2)EJ') flag++;
if (ver =='15.0(2)EJ1') flag++;
if (ver =='15.0(2)EZ') flag++;
if (ver =='15.0(2)SE') flag++;
if (ver =='15.0(2)SE1') flag++;
if (ver =='15.0(2)SE2') flag++;
if (ver =='15.0(2)SE3') flag++;
if (ver =='15.0(2)SE4') flag++;
if (ver =='15.0(2)SE5') flag++;
if (ver =='15.0(2)SE6') flag++;
if (ver =='15.0(2)SE7') flag++;
if (ver =='15.1(1)SY') flag++;
if (ver =='15.1(1)SY1') flag++;
if (ver =='15.1(1)SY2') flag++;
if (ver =='15.1(1)SY3') flag++;
if (ver =='15.1(1)SY4') flag++;
if (ver =='15.1(1)SY5') flag++;
if (ver =='15.1(2)SG') flag++;
if (ver =='15.1(2)SG1') flag++;
if (ver =='15.1(2)SG2') flag++;
if (ver =='15.1(2)SG3') flag++;
if (ver =='15.1(2)SG4') flag++;
if (ver =='15.1(2)SG5') flag++;
if (ver =='15.1(2)SY') flag++;
if (ver =='15.1(2)SY1') flag++;
if (ver =='15.1(2)SY2') flag++;
if (ver =='15.1(2)SY3') flag++;
if (ver =='15.1(2)SY4') flag++;
if (ver =='15.1(2)SY4a') flag++;
if (ver =='15.1(2)SY5') flag++;
if (ver =='15.2(1)E') flag++;
if (ver =='15.2(1)E1') flag++;
if (ver =='15.2(1)E2') flag++;
if (ver =='15.2(1)E3') flag++;
if (ver =='15.2(1)SY') flag++;
if (ver =='15.2(1)SY0a') flag++;
if (ver =='15.2(2)E') flag++;
if (ver =='15.2(2)E1') flag++;
if (ver =='15.2(2)E2') flag++;
if (ver =='15.2(2)EA1') flag++;
if (ver =='15.2(2a)E1') flag++;
if (ver =='15.2(3)E') flag++;
if (ver =='15.2(3)E1') flag++;
if (ver =='15.2(3a)E') flag++;
if (ver =='15.2(4)S') flag++;
if (ver =='15.2(4)S1') flag++;
if (ver =='15.2(4)S2') flag++;
if (ver =='15.2(4)S3') flag++;
if (ver =='15.2(4)S3a') flag++;
if (ver =='15.2(4)S4') flag++;
if (ver =='15.2(4)S4a') flag++;
if (ver =='15.2(4)S5') flag++;
if (ver =='15.2(4)S6') flag++;
if (ver =='15.3(1)S') flag++;
if (ver =='15.3(1)S2') flag++;
if (ver =='15.3(2)S') flag++;
if (ver =='15.3(2)S0a') flag++;
if (ver =='15.3(2)S1') flag++;
if (ver =='15.3(2)S2') flag++;
if (ver =='15.3(3)S') flag++;
if (ver =='15.3(3)S1') flag++;
if (ver =='15.3(3)S2') flag++;
if (ver =='15.3(3)S3') flag++;
if (ver =='15.3(3)S4') flag++;
if (ver =='15.4(1)S') flag++;
if (ver =='15.4(1)S1') flag++;
if (ver =='15.4(1)S2') flag++;
if (ver =='15.4(1)S3') flag++;
if (ver =='15.4(2)S') flag++;
if (ver =='15.4(2)S1') flag++;
if (ver =='15.4(2)S2') flag++;
if (ver =='15.5(1)S') flag++;
if (ver =='15.5(1)S1') flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-ipv6-snooping-policies", "show ipv6 snooping policies");
  if (check_cisco_result(buf))
  {
    if ("Snooping" >< buf) flag = 1;
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
      '\n  Cisco bug IDs     : CSCuo04400 / CSCus19794' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
