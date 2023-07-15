#TRUSTED 31146feff644ed4f782501fdb69de34d401dfdd26859e080dd877525c6e9f65fdd9c739bfe89a3117ef47ddda7e5bcd851e71a2c88544dbde22b605c15063e6d854c31aa54002f83976bb7e417ee63e7f09993da7aaafe565b9d3b828187b58919a7f7f9f8fa5a2939560ad9857275ea9fe6e632f1bd5da21490744f6d510358eb39567d9fa3d71ff71331cd65cfe8a033d1d1c1e536aa26536ff2a8d51415a0980b7d851f2f9d51948512857a3ba694da92eb0260e0b5bbd631de8aebf49975470bb298bd376e0a430f25a36c046ca865d6d7f8d67239f2e3ebc338b9bbfefd6c12978a758f4b38deee8d4b06e57cc4662c0dc1c40a9bd4f15d5aa234b19f55b80fd64a05b0df8993793988ded4075b8aef69e6dffa97421b195b16048aefe88e8a1925d2c76d62cdf5648cc6fb2c20e3d821410620769edccd519bd39dfdc8721974f7eb2dbe90629189dada23326f122bb4eb9e66e098a05ec3987d799c761a24131ab7a1829530971b59b4b3f29ba89bfa391ea903fd02d2676831366bcb762e22f1195446a477a5d2c7186078954373005fe0894d5e8852aabb2d0578968ca1f80a0d608e0a22e0329378385901a905c0674eaf5dbb0caad755c8cc9daf424b23650714cf757ef2653f69908788e13034c0d2f11e23f7c9f5f6f86db940a5f4d5a8c0ca1184d3038ddc3d93c51b53674bc216259cd1b8006d2baba1993c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014a9.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49028);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-3803");
 script_bugtraq_id(31366);
 script_name(english:"Cisco IOS MPLS VPN May Leak Information - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Devices running Cisco IOS versions 12.0S, 12.2, 12.3 or 12.4 and
configured for Multiprotocol Label Switching (MPLS) Virtual Private
Networks (VPNs) or VPN Routing and Forwarding Lite (VRF Lite) and using
Border Gateway Protocol (BGP) between Customer Edge (CE) and Provider
Edge (PE) devices may permit information to propagate between VPNs.
Workarounds are available to help mitigate this vulnerability.
 This issue is triggered by a logic error when processing extended
communities on the PE device.
 This issue cannot be deterministically exploited by an attacker.

 Cisco has released free software updates that address these
vulnerabilities. Workarounds that mitigate these vulnerabilities are
available.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bfd4ca4");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014a9.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d93c67d5");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-vpn.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCec12299");
 script_xref(name:"CISCO-BUG-ID", value:"CSCee83237");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-vpn");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(6)XT') flag++;
else if (version == '12.4(6)XP') flag++;
else if (version == '12.4(14)XK') flag++;
else if (version == '12.4(11)XJ') flag++;
else if (version == '12.4(9)XG1') flag++;
else if (version == '12.4(9)XG') flag++;
else if (version == '12.4(6)XE2') flag++;
else if (version == '12.4(6)XE1') flag++;
else if (version == '12.4(6)XE') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(11)T1') flag++;
else if (version == '12.4(11)T') flag++;
else if (version == '12.4(9)T2') flag++;
else if (version == '12.4(9)T1') flag++;
else if (version == '12.4(9)T') flag++;
else if (version == '12.4(6)T6') flag++;
else if (version == '12.4(6)T5') flag++;
else if (version == '12.4(6)T4') flag++;
else if (version == '12.4(6)T3') flag++;
else if (version == '12.4(6)T2') flag++;
else if (version == '12.4(6)T1') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(11)SW') flag++;
else if (version == '12.4(12)') flag++;
else if (version == '12.4(10b)') flag++;
else if (version == '12.4(10a)') flag++;
else if (version == '12.4(10)') flag++;
else if (version == '12.4(8c)') flag++;
else if (version == '12.4(8b)') flag++;
else if (version == '12.4(8a)') flag++;
else if (version == '12.4(8)') flag++;
else if (version == '12.4(7d)') flag++;
else if (version == '12.4(7c)') flag++;
else if (version == '12.4(7b)') flag++;
else if (version == '12.4(7a)') flag++;
else if (version == '12.4(7)') flag++;
else if (version == '12.4(5b)') flag++;
else if (version == '12.4(5a)') flag++;
else if (version == '12.4(5)') flag++;
else if (version == '12.4(3g)') flag++;
else if (version == '12.4(3f)') flag++;
else if (version == '12.4(3e)') flag++;
else if (version == '12.4(3d)') flag++;
else if (version == '12.4(3c)') flag++;
else if (version == '12.4(3b)') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1c)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(11)YZ1') flag++;
else if (version == '12.3(11)YZ') flag++;
else if (version == '12.3(14)YX4') flag++;
else if (version == '12.3(14)YX3') flag++;
else if (version == '12.3(14)YX2') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YX') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ8') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(14)YM9') flag++;
else if (version == '12.3(14)YM8') flag++;
else if (version == '12.3(14)YM7') flag++;
else if (version == '12.3(14)YM6') flag++;
else if (version == '12.3(14)YM5') flag++;
else if (version == '12.3(14)YM4') flag++;
else if (version == '12.3(14)YM3') flag++;
else if (version == '12.3(14)YM2') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(11)YJ') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T9') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T11') flag++;
else if (version == '12.3(11)T10') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.2(28)ZX') flag++;
else if (version == '12.2(28b)ZV1') flag++;
else if (version == '12.2(28)ZV2') flag++;
else if (version == '12.2(28)VZ') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(18)SXE6b') flag++;
else if (version == '12.2(18)SXE6a') flag++;
else if (version == '12.2(18)SXE6') flag++;
else if (version == '12.2(18)SXE5') flag++;
else if (version == '12.2(18)SXE4') flag++;
else if (version == '12.2(18)SXE3') flag++;
else if (version == '12.2(18)SXE2') flag++;
else if (version == '12.2(18)SXE1') flag++;
else if (version == '12.2(18)SXE') flag++;
else if (version == '12.2(29b)SV') flag++;
else if (version == '12.2(29a)SV1') flag++;
else if (version == '12.2(29a)SV') flag++;
else if (version == '12.2(29)SV3') flag++;
else if (version == '12.2(29)SV2') flag++;
else if (version == '12.2(29)SV1') flag++;
else if (version == '12.2(29)SV') flag++;
else if (version == '12.2(28)SV2') flag++;
else if (version == '12.2(28)SV1') flag++;
else if (version == '12.2(28)SV') flag++;
else if (version == '12.2(27)SV5') flag++;
else if (version == '12.2(27)SV4') flag++;
else if (version == '12.2(27)SV3') flag++;
else if (version == '12.2(27)SV2') flag++;
else if (version == '12.2(27)SV1') flag++;
else if (version == '12.2(27)SV') flag++;
else if (version == '12.2(26)SV1') flag++;
else if (version == '12.2(26)SV') flag++;
else if (version == '12.2(29)SM1') flag++;
else if (version == '12.2(29)SM') flag++;
else if (version == '12.2(31)SGA7') flag++;
else if (version == '12.2(31)SGA6') flag++;
else if (version == '12.2(31)SGA5') flag++;
else if (version == '12.2(31)SGA4') flag++;
else if (version == '12.2(31)SGA3') flag++;
else if (version == '12.2(31)SGA2') flag++;
else if (version == '12.2(31)SGA1') flag++;
else if (version == '12.2(31)SGA') flag++;
else if (version == '12.2(31)SG3') flag++;
else if (version == '12.2(31)SG2') flag++;
else if (version == '12.2(31)SG1') flag++;
else if (version == '12.2(31)SG') flag++;
else if (version == '12.2(27)SBC5') flag++;
else if (version == '12.2(27)SBC4') flag++;
else if (version == '12.2(27)SBC3') flag++;
else if (version == '12.2(27)SBC2') flag++;
else if (version == '12.2(27)SBC1') flag++;
else if (version == '12.2(27)SBC') flag++;
else if (version == '12.2(28)SB4') flag++;
else if (version == '12.2(28)SB3') flag++;
else if (version == '12.2(28)SB2') flag++;
else if (version == '12.2(28)SB1') flag++;
else if (version == '12.2(28)SB') flag++;
else if (version == '12.2(30)S1') flag++;
else if (version == '12.2(30)S') flag++;
else if (version == '12.2(18)IXC') flag++;
else if (version == '12.2(18)IXB2') flag++;
else if (version == '12.2(18)IXB1') flag++;
else if (version == '12.2(18)IXB') flag++;
else if (version == '12.2(18)IXA') flag++;
else if (version == '12.0(31)S2') flag++;
else if (version == '12.0(31)S1') flag++;
else if (version == '12.0(31)S') flag++;
else if (version == '12.0(30)S4') flag++;
else if (version == '12.0(30)S3') flag++;
else if (version == '12.0(30)S2') flag++;
else if (version == '12.0(30)S1') flag++;
else if (version == '12.0(30)S') flag++;
else if (version == '12.0(28)S6') flag++;
else if (version == '12.0(28)S5') flag++;
else if (version == '12.0(28)S4') flag++;
else if (version == '12.0(28)S3') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"router bgp[^!]*address-family ipv4 vrf", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"router bgp[^!]*address-family ipv6 vrf", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
