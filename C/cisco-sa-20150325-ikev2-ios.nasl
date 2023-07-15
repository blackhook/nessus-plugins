#TRUSTED a239abd65240c884ce482f4be5080749eadb4302e3d80bfe3dbc3014b914ba0de37d8358aaac29119e96a6d6a715ae1493a3d18f89701b593bf61edc372aa4c33d81392ff41f3bafe68a72820b9d6d62087879c6ddfbad5f9055dd74ea0390ba0d5e4e908d4b9ef76d65fa23329a04fb858e80635e47c3d6d69ac115dc0286f7793300cc9373b111c3b7ed9a211bf0d48ecf166d465e73651a317d3ba07689361f9c571e7f995bf7da0a131b80c2b87b81432ea87d096c3ca7667a773cc5eea502bc857710bd5084e088acde98f1158264fb039202c08fd8a4e27c990fe478a486cb9aa8be0bc2f83c5626d7b0fbd6760f94d1d9d3dca3d314197f8b3885fb75b91feffbca3a680974169793808f391bb582f5a40b4e1a338430ce11d008e573324a3b46a557bca57e51b3310912056403b9af566c470fab6b604ba545a3a6af61dfcf400ab852c3b995d4f3df42b9b8a7fa8b1b12c035cc07bd0c3bfda5d96257fffb51520ac08bc298615bbcbd3fdec87f1703b32a6cfc5ec3085c7d2685a52b03ea2ca5c5627d5a88e3ea8cd6a7abb0c3c0db42a67582d8e59ba99f0db720fe2b31726922f8bba39657674fc26c154bb98985b7fe151994a092739f154443811edbbff17213a299b768c8b3149639dd79c263f799cb9295db84af0c7d22da41bccf7d842c010bd5ec5160f2deb8e2d68af999831ea7d3f0cb96118c74af8e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82574);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0642", "CVE-2015-0643");
  script_bugtraq_id(73333);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum36951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo75572");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ikev2");

  script_name(english:"Cisco IOS IKEv2 DoS (cisco-sa-20150325-ikev2)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Internet Key Exchange version 2 (IKEv2) subsystem due to
improper handling of specially crafted IKEv2 packets. A remote,
unauthenticated attacker can exploit this issue to cause a device
reload or exhaust memory resources.

Note that this issue only affects devices with IKEv1 or ISAKMP
enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10464ee0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37815");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37816");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ( ver == '12.2(58)EX' ) flag++;
if ( ver == '12.2(58)EY' ) flag++;
if ( ver == '12.2(58)EY1' ) flag++;
if ( ver == '12.2(58)EY2' ) flag++;
if ( ver == '12.2(58)EZ' ) flag++;
if ( ver == '12.2(60)EZ' ) flag++;
if ( ver == '12.2(60)EZ1' ) flag++;
if ( ver == '12.2(60)EZ2' ) flag++;
if ( ver == '12.2(60)EZ3' ) flag++;
if ( ver == '12.2(60)EZ4' ) flag++;
if ( ver == '12.2(60)EZ5' ) flag++;
if ( ver == '12.2(60)EZ6' ) flag++;
if ( ver == '12.2(33)IRD1' ) flag++;
if ( ver == '12.2(33)IRE3' ) flag++;
if ( ver == '12.2(58)SE2' ) flag++;
if ( ver == '12.2(44)SQ1' ) flag++;
if ( ver == '12.2(33)SXI4b' ) flag++;
if ( ver == '12.4(22)GC1' ) flag++;
if ( ver == '12.4(24)GC1' ) flag++;
if ( ver == '12.4(24)GC3' ) flag++;
if ( ver == '12.4(24)GC3a' ) flag++;
if ( ver == '12.4(24)GC4' ) flag++;
if ( ver == '12.4(24)GC5' ) flag++;
if ( ver == '12.4(25e)JAM1' ) flag++;
if ( ver == '12.4(25e)JAP1m' ) flag++;
if ( ver == '12.4(25e)JAZ1' ) flag++;
if ( ver == '12.4(22)MD' ) flag++;
if ( ver == '12.4(22)MD1' ) flag++;
if ( ver == '12.4(22)MD2' ) flag++;
if ( ver == '12.4(24)MD' ) flag++;
if ( ver == '12.4(24)MD1' ) flag++;
if ( ver == '12.4(24)MD2' ) flag++;
if ( ver == '12.4(24)MD3' ) flag++;
if ( ver == '12.4(24)MD4' ) flag++;
if ( ver == '12.4(24)MD5' ) flag++;
if ( ver == '12.4(24)MD6' ) flag++;
if ( ver == '12.4(24)MD7' ) flag++;
if ( ver == '12.4(22)MDA' ) flag++;
if ( ver == '12.4(22)MDA1' ) flag++;
if ( ver == '12.4(22)MDA2' ) flag++;
if ( ver == '12.4(22)MDA3' ) flag++;
if ( ver == '12.4(22)MDA4' ) flag++;
if ( ver == '12.4(22)MDA5' ) flag++;
if ( ver == '12.4(22)MDA6' ) flag++;
if ( ver == '12.4(24)MDA1' ) flag++;
if ( ver == '12.4(24)MDA10' ) flag++;
if ( ver == '12.4(24)MDA11' ) flag++;
if ( ver == '12.4(24)MDA12' ) flag++;
if ( ver == '12.4(24)MDA13' ) flag++;
if ( ver == '12.4(24)MDA2' ) flag++;
if ( ver == '12.4(24)MDA3' ) flag++;
if ( ver == '12.4(24)MDA4' ) flag++;
if ( ver == '12.4(24)MDA5' ) flag++;
if ( ver == '12.4(24)MDA6' ) flag++;
if ( ver == '12.4(24)MDA7' ) flag++;
if ( ver == '12.4(24)MDA8' ) flag++;
if ( ver == '12.4(24)MDA9' ) flag++;
if ( ver == '12.4(24)MDB' ) flag++;
if ( ver == '12.4(24)MDB1' ) flag++;
if ( ver == '12.4(24)MDB10' ) flag++;
if ( ver == '12.4(24)MDB11' ) flag++;
if ( ver == '12.4(24)MDB12' ) flag++;
if ( ver == '12.4(24)MDB13' ) flag++;
if ( ver == '12.4(24)MDB14' ) flag++;
if ( ver == '12.4(24)MDB15' ) flag++;
if ( ver == '12.4(24)MDB16' ) flag++;
if ( ver == '12.4(24)MDB17' ) flag++;
if ( ver == '12.4(24)MDB18' ) flag++;
if ( ver == '12.4(24)MDB19' ) flag++;
if ( ver == '12.4(24)MDB3' ) flag++;
if ( ver == '12.4(24)MDB4' ) flag++;
if ( ver == '12.4(24)MDB5' ) flag++;
if ( ver == '12.4(24)MDB5a' ) flag++;
if ( ver == '12.4(24)MDB6' ) flag++;
if ( ver == '12.4(24)MDB7' ) flag++;
if ( ver == '12.4(24)MDB8' ) flag++;
if ( ver == '12.4(24)MDB9' ) flag++;
if ( ver == '12.4(22)T' ) flag++;
if ( ver == '12.4(22)T1' ) flag++;
if ( ver == '12.4(22)T2' ) flag++;
if ( ver == '12.4(22)T3' ) flag++;
if ( ver == '12.4(22)T4' ) flag++;
if ( ver == '12.4(22)T5' ) flag++;
if ( ver == '12.4(24)T' ) flag++;
if ( ver == '12.4(24)T1' ) flag++;
if ( ver == '12.4(24)T2' ) flag++;
if ( ver == '12.4(24)T3' ) flag++;
if ( ver == '12.4(24)T3e' ) flag++;
if ( ver == '12.4(24)T3f' ) flag++;
if ( ver == '12.4(24)T4' ) flag++;
if ( ver == '12.4(24)T4a' ) flag++;
if ( ver == '12.4(24)T4b' ) flag++;
if ( ver == '12.4(24)T4c' ) flag++;
if ( ver == '12.4(24)T4d' ) flag++;
if ( ver == '12.4(24)T4e' ) flag++;
if ( ver == '12.4(24)T4f' ) flag++;
if ( ver == '12.4(24)T4l' ) flag++;
if ( ver == '12.4(24)T5' ) flag++;
if ( ver == '12.4(24)T6' ) flag++;
if ( ver == '12.4(24)T7' ) flag++;
if ( ver == '12.4(24)T8' ) flag++;
if ( ver == '12.4(22)XR1' ) flag++;
if ( ver == '12.4(22)XR10' ) flag++;
if ( ver == '12.4(22)XR11' ) flag++;
if ( ver == '12.4(22)XR12' ) flag++;
if ( ver == '12.4(22)XR2' ) flag++;
if ( ver == '12.4(22)XR3' ) flag++;
if ( ver == '12.4(22)XR4' ) flag++;
if ( ver == '12.4(22)XR5' ) flag++;
if ( ver == '12.4(22)XR6' ) flag++;
if ( ver == '12.4(22)XR7' ) flag++;
if ( ver == '12.4(22)XR8' ) flag++;
if ( ver == '12.4(22)XR9' ) flag++;
if ( ver == '12.4(22)YB' ) flag++;
if ( ver == '12.4(22)YB1' ) flag++;
if ( ver == '12.4(22)YB2' ) flag++;
if ( ver == '12.4(22)YB3' ) flag++;
if ( ver == '12.4(22)YB4' ) flag++;
if ( ver == '12.4(22)YB5' ) flag++;
if ( ver == '12.4(22)YB6' ) flag++;
if ( ver == '12.4(22)YB7' ) flag++;
if ( ver == '12.4(22)YB8' ) flag++;
if ( ver == '12.4(22)YD' ) flag++;
if ( ver == '12.4(22)YD1' ) flag++;
if ( ver == '12.4(22)YD2' ) flag++;
if ( ver == '12.4(22)YD3' ) flag++;
if ( ver == '12.4(22)YD4' ) flag++;
if ( ver == '12.4(22)YE' ) flag++;
if ( ver == '12.4(22)YE1' ) flag++;
if ( ver == '12.4(22)YE2' ) flag++;
if ( ver == '12.4(22)YE3' ) flag++;
if ( ver == '12.4(22)YE4' ) flag++;
if ( ver == '12.4(22)YE5' ) flag++;
if ( ver == '12.4(22)YE6' ) flag++;
if ( ver == '12.4(24)YE' ) flag++;
if ( ver == '12.4(24)YE1' ) flag++;
if ( ver == '12.4(24)YE2' ) flag++;
if ( ver == '12.4(24)YE3' ) flag++;
if ( ver == '12.4(24)YE3a' ) flag++;
if ( ver == '12.4(24)YE3b' ) flag++;
if ( ver == '12.4(24)YE3c' ) flag++;
if ( ver == '12.4(24)YE3d' ) flag++;
if ( ver == '12.4(24)YE3e' ) flag++;
if ( ver == '12.4(24)YE4' ) flag++;
if ( ver == '12.4(24)YE5' ) flag++;
if ( ver == '12.4(24)YE6' ) flag++;
if ( ver == '12.4(24)YE7' ) flag++;
if ( ver == '12.4(24)YG1' ) flag++;
if ( ver == '12.4(24)YG2' ) flag++;
if ( ver == '12.4(24)YG3' ) flag++;
if ( ver == '12.4(24)YG4' ) flag++;
if ( ver == '15.0(2)EB' ) flag++;
if ( ver == '15.0(2)EC' ) flag++;
if ( ver == '15.0(2)ED' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(2)EH' ) flag++;
if ( ver == '15.0(2)EJ' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EK1' ) flag++;
if ( ver == '15.0(1)EX' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX2' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(1)EY' ) flag++;
if ( ver == '15.0(1)EY1' ) flag++;
if ( ver == '15.0(1)EY2' ) flag++;
if ( ver == '15.0(2)EY' ) flag++;
if ( ver == '15.0(2)EY1' ) flag++;
if ( ver == '15.0(2)EY3' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(1)M' ) flag++;
if ( ver == '15.0(1)M1' ) flag++;
if ( ver == '15.0(1)M10' ) flag++;
if ( ver == '15.0(1)M2' ) flag++;
if ( ver == '15.0(1)M3' ) flag++;
if ( ver == '15.0(1)M4' ) flag++;
if ( ver == '15.0(1)M5' ) flag++;
if ( ver == '15.0(1)M6' ) flag++;
if ( ver == '15.0(1)M7' ) flag++;
if ( ver == '15.0(1)M8' ) flag++;
if ( ver == '15.0(1)M9' ) flag++;
if ( ver == '15.0(1)MR' ) flag++;
if ( ver == '15.0(2)MR' ) flag++;
if ( ver == '15.0(1)S' ) flag++;
if ( ver == '15.0(1)S1' ) flag++;
if ( ver == '15.0(1)S2' ) flag++;
if ( ver == '15.0(1)S3a' ) flag++;
if ( ver == '15.0(1)S4' ) flag++;
if ( ver == '15.0(1)S4a' ) flag++;
if ( ver == '15.0(1)S5' ) flag++;
if ( ver == '15.0(1)S6' ) flag++;
if ( ver == '15.0(1)SE' ) flag++;
if ( ver == '15.0(1)SE1' ) flag++;
if ( ver == '15.0(1)SE2' ) flag++;
if ( ver == '15.0(1)SE3' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE7' ) flag++;
if ( ver == '15.0(1)XA' ) flag++;
if ( ver == '15.0(1)XA1' ) flag++;
if ( ver == '15.0(1)XA2' ) flag++;
if ( ver == '15.0(1)XA3' ) flag++;
if ( ver == '15.0(1)XA4' ) flag++;
if ( ver == '15.0(1)XA5' ) flag++;
if ( ver == '15.1(2)EY' ) flag++;
if ( ver == '15.1(2)EY1a' ) flag++;
if ( ver == '15.1(2)EY2' ) flag++;
if ( ver == '15.1(2)EY2a' ) flag++;
if ( ver == '15.1(2)EY3' ) flag++;
if ( ver == '15.1(2)EY4' ) flag++;
if ( ver == '15.1(2)GC' ) flag++;
if ( ver == '15.1(2)GC1' ) flag++;
if ( ver == '15.1(2)GC2' ) flag++;
if ( ver == '15.1(4)GC' ) flag++;
if ( ver == '15.1(4)GC1' ) flag++;
if ( ver == '15.1(4)GC2' ) flag++;
if ( ver == '15.1(4)M' ) flag++;
if ( ver == '15.1(4)M1' ) flag++;
if ( ver == '15.1(4)M2' ) flag++;
if ( ver == '15.1(4)M3' ) flag++;
if ( ver == '15.1(4)M3a' ) flag++;
if ( ver == '15.1(4)M4' ) flag++;
if ( ver == '15.1(4)M5' ) flag++;
if ( ver == '15.1(4)M6' ) flag++;
if ( ver == '15.1(4)M7' ) flag++;
if ( ver == '15.1(4)M8' ) flag++;
if ( ver == '15.1(4)M9' ) flag++;
if ( ver == '15.1(1)MR' ) flag++;
if ( ver == '15.1(1)MR1' ) flag++;
if ( ver == '15.1(1)MR2' ) flag++;
if ( ver == '15.1(1)MR3' ) flag++;
if ( ver == '15.1(1)MR4' ) flag++;
if ( ver == '15.1(3)MR' ) flag++;
if ( ver == '15.1(3)MRA' ) flag++;
if ( ver == '15.1(3)MRA1' ) flag++;
if ( ver == '15.1(3)MRA2' ) flag++;
if ( ver == '15.1(1)S' ) flag++;
if ( ver == '15.1(1)S1' ) flag++;
if ( ver == '15.1(1)S2' ) flag++;
if ( ver == '15.1(2)S' ) flag++;
if ( ver == '15.1(2)S1' ) flag++;
if ( ver == '15.1(2)S2' ) flag++;
if ( ver == '15.1(3)S' ) flag++;
if ( ver == '15.1(3)S0a' ) flag++;
if ( ver == '15.1(3)S1' ) flag++;
if ( ver == '15.1(3)S2' ) flag++;
if ( ver == '15.1(3)S3' ) flag++;
if ( ver == '15.1(3)S4' ) flag++;
if ( ver == '15.1(3)S5' ) flag++;
if ( ver == '15.1(3)S5a' ) flag++;
if ( ver == '15.1(3)S6' ) flag++;
if ( ver == '15.1(1)SG' ) flag++;
if ( ver == '15.1(1)SG1' ) flag++;
if ( ver == '15.1(1)SG2' ) flag++;
if ( ver == '15.1(2)SG' ) flag++;
if ( ver == '15.1(2)SG1' ) flag++;
if ( ver == '15.1(2)SG2' ) flag++;
if ( ver == '15.1(2)SG3' ) flag++;
if ( ver == '15.1(2)SG4' ) flag++;
if ( ver == '15.1(2)SG5' ) flag++;
if ( ver == '15.1(2)SNG' ) flag++;
if ( ver == '15.1(2)SNH' ) flag++;
if ( ver == '15.1(2)SNI' ) flag++;
if ( ver == '15.1(2)SNI1' ) flag++;
if ( ver == '15.1(1)SY' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY4' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY4' ) flag++;
if ( ver == '15.1(2)SY4a' ) flag++;
if ( ver == '15.1(1)T' ) flag++;
if ( ver == '15.1(1)T1' ) flag++;
if ( ver == '15.1(1)T2' ) flag++;
if ( ver == '15.1(1)T3' ) flag++;
if ( ver == '15.1(1)T4' ) flag++;
if ( ver == '15.1(1)T5' ) flag++;
if ( ver == '15.1(2)T' ) flag++;
if ( ver == '15.1(2)T0a' ) flag++;
if ( ver == '15.1(2)T1' ) flag++;
if ( ver == '15.1(2)T2' ) flag++;
if ( ver == '15.1(2)T2a' ) flag++;
if ( ver == '15.1(2)T3' ) flag++;
if ( ver == '15.1(2)T4' ) flag++;
if ( ver == '15.1(2)T5' ) flag++;
if ( ver == '15.1(3)T' ) flag++;
if ( ver == '15.1(3)T1' ) flag++;
if ( ver == '15.1(3)T2' ) flag++;
if ( ver == '15.1(3)T3' ) flag++;
if ( ver == '15.1(3)T4' ) flag++;
if ( ver == '15.1(1)XB' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(1)EX' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(1)GC' ) flag++;
if ( ver == '15.2(1)GC1' ) flag++;
if ( ver == '15.2(1)GC2' ) flag++;
if ( ver == '15.2(2)GC' ) flag++;
if ( ver == '15.2(3)GC' ) flag++;
if ( ver == '15.2(3)GC1' ) flag++;
if ( ver == '15.2(4)GC' ) flag++;
if ( ver == '15.2(4)GC1' ) flag++;
if ( ver == '15.2(4)GC2' ) flag++;
if ( ver == '15.2(4)GC3' ) flag++;
if ( ver == '15.2(2)JA' ) flag++;
if ( ver == '15.2(2)JA1' ) flag++;
if ( ver == '15.2(4)JA' ) flag++;
if ( ver == '15.2(4)JA1' ) flag++;
if ( ver == '15.2(2)JAX' ) flag++;
if ( ver == '15.2(2)JAX1' ) flag++;
if ( ver == '15.2(2)JB' ) flag++;
if ( ver == '15.2(2)JB1' ) flag++;
if ( ver == '15.2(2)JB2' ) flag++;
if ( ver == '15.2(2)JB3' ) flag++;
if ( ver == '15.2(2)JB4' ) flag++;
if ( ver == '15.2(4)JB' ) flag++;
if ( ver == '15.2(4)JB1' ) flag++;
if ( ver == '15.2(4)JB2' ) flag++;
if ( ver == '15.2(4)JB3' ) flag++;
if ( ver == '15.2(4)JB3a' ) flag++;
if ( ver == '15.2(4)JB3b' ) flag++;
if ( ver == '15.2(4)JB3h' ) flag++;
if ( ver == '15.2(4)JB3s' ) flag++;
if ( ver == '15.2(4)JB4' ) flag++;
if ( ver == '15.2(4)JB5' ) flag++;
if ( ver == '15.2(4)JB5h' ) flag++;
if ( ver == '15.2(4)JB5m' ) flag++;
if ( ver == '15.2(4)JB50' ) flag++;
if ( ver == '15.2(4)JB6' ) flag++;
if ( ver == '15.2(2)JN1' ) flag++;
if ( ver == '15.2(2)JN2' ) flag++;
if ( ver == '15.2(4)JN' ) flag++;
if ( ver == '15.2(4)M' ) flag++;
if ( ver == '15.2(4)M1' ) flag++;
if ( ver == '15.2(4)M2' ) flag++;
if ( ver == '15.2(4)M3' ) flag++;
if ( ver == '15.2(4)M4' ) flag++;
if ( ver == '15.2(4)M5' ) flag++;
if ( ver == '15.2(4)M6' ) flag++;
if ( ver == '15.2(4)M6a' ) flag++;
if ( ver == '15.2(4)M7' ) flag++;
if ( ver == '15.2(1)S' ) flag++;
if ( ver == '15.2(1)S1' ) flag++;
if ( ver == '15.2(1)S2' ) flag++;
if ( ver == '15.2(2)S' ) flag++;
if ( ver == '15.2(2)S0a' ) flag++;
if ( ver == '15.2(2)S0c' ) flag++;
if ( ver == '15.2(2)S1' ) flag++;
if ( ver == '15.2(2)S2' ) flag++;
if ( ver == '15.2(4)S' ) flag++;
if ( ver == '15.2(4)S1' ) flag++;
if ( ver == '15.2(4)S2' ) flag++;
if ( ver == '15.2(4)S3' ) flag++;
if ( ver == '15.2(4)S3a' ) flag++;
if ( ver == '15.2(4)S4' ) flag++;
if ( ver == '15.2(4)S4a' ) flag++;
if ( ver == '15.2(4)S5' ) flag++;
if ( ver == '15.2(4)S6' ) flag++;
if ( ver == '15.2(2)SNG' ) flag++;
if ( ver == '15.2(2)SNH1' ) flag++;
if ( ver == '15.2(2)SNI' ) flag++;
if ( ver == '15.2(1)SY' ) flag++;
if ( ver == '15.2(1)T' ) flag++;
if ( ver == '15.2(1)T1' ) flag++;
if ( ver == '15.2(1)T2' ) flag++;
if ( ver == '15.2(1)T3' ) flag++;
if ( ver == '15.2(1)T3a' ) flag++;
if ( ver == '15.2(1)T4' ) flag++;
if ( ver == '15.2(2)T' ) flag++;
if ( ver == '15.2(2)T1' ) flag++;
if ( ver == '15.2(2)T2' ) flag++;
if ( ver == '15.2(2)T3' ) flag++;
if ( ver == '15.2(2)T4' ) flag++;
if ( ver == '15.2(3)T' ) flag++;
if ( ver == '15.2(3)T1' ) flag++;
if ( ver == '15.2(3)T2' ) flag++;
if ( ver == '15.2(3)T3' ) flag++;
if ( ver == '15.2(3)T4' ) flag++;
if ( ver == '15.3(3)JA' ) flag++;
if ( ver == '15.3(3)JA1' ) flag++;
if ( ver == '15.3(3)JA1m' ) flag++;
if ( ver == '15.3(3)JA1n' ) flag++;
if ( ver == '15.3(3)JAA' ) flag++;
if ( ver == '15.3(3)JAB' ) flag++;
if ( ver == '15.3(3)JAB1' ) flag++;
if ( ver == '15.3(3)JN' ) flag++;
if ( ver == '15.3(3)JNB' ) flag++;
if ( ver == '15.3(3)M' ) flag++;
if ( ver == '15.3(3)M1' ) flag++;
if ( ver == '15.3(3)M2' ) flag++;
if ( ver == '15.3(3)M4' ) flag++;
if ( ver == '15.3(1)S' ) flag++;
if ( ver == '15.3(1)S1' ) flag++;
if ( ver == '15.3(1)S2' ) flag++;
if ( ver == '15.3(2)S' ) flag++;
if ( ver == '15.3(2)S0a' ) flag++;
if ( ver == '15.3(2)S1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S1a' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(1)T' ) flag++;
if ( ver == '15.3(1)T1' ) flag++;
if ( ver == '15.3(1)T2' ) flag++;
if ( ver == '15.3(1)T3' ) flag++;
if ( ver == '15.3(1)T4' ) flag++;
if ( ver == '15.3(2)T' ) flag++;
if ( ver == '15.3(2)T1' ) flag++;
if ( ver == '15.3(2)T2' ) flag++;
if ( ver == '15.3(2)T3' ) flag++;
if ( ver == '15.3(2)T4' ) flag++;
if ( ver == '15.4(1)CG' ) flag++;
if ( ver == '15.4(1)CG1' ) flag++;
if ( ver == '15.4(2)CG' ) flag++;
if ( ver == '15.4(3)M' ) flag++;
if ( ver == '15.4(3)M1' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(3)S1' ) flag++;
if ( ver == '15.4(1)T' ) flag++;
if ( ver == '15.4(1)T1' ) flag++;
if ( ver == '15.4(1)T2' ) flag++;
if ( ver == '15.4(1)T3' ) flag++;
if ( ver == '15.4(2)T' ) flag++;
if ( ver == '15.4(2)T1' ) flag++;
if ( ver == '15.4(2)T2' ) flag++;

# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if (!flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
    if (check_cisco_result(buf))
    {
      if (
        preg(multiline:TRUE, pattern:pat, string:buf)
      ) flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = 1;
      override = 1;
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCum36951 and CSCuo75572' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
