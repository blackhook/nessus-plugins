#TRUSTED 8113acc38675928538bc58394cb60aa295cdbf0f0ec27b7c99c116e08877de161bfe74080fe1e79dbbbfd05807c586f1d0f1f7901e89687008fec96fd23324a41654002e997fab5f5c0f9efd9ffd6274906a479bb28873ffdd508f266b1a00c7d40b3efab4bb0383ef541cd36356395d0d8079efcc365dfa7c7dbb97ab06db60f28de02761c857c380c6ef0a409ee844b1e85bb948076d6af2a9cbf15e0eb5d2ff6cb69216bc3c8aeb16a4618a313309901f60fc9b0aaa4a79a23f05f8c3173b43eed5421a69ec6b5eb0f2a7b0f5f9102d023c476cf036dcaf95e9e3182f57c687a3f1b7c3b99bcb8b0ad575478340bd879e2680c0e5669ad3bd370203de231a3de9a9a9b6788afff9efa3248b9e0de3dde30c90e3ecc852c51ef47b2015b0982aef74dfe29b9076e77b31ff19545ec1d881493c170b61817513cfa4ed8361fa60787940024921e04412b99376ef033028a6d3af61c9f0d82622eb9a887c64ab475e1d57b941f50d11ef98ec2f5e3872fe35bb768cdd5fa5bd36940eb693651876ed70d9e249be4c4567854dcf2e14210fbefdd0538227a57871dd6f07cfe7fc355060203c5bb5905af4d6f05cb7e16ca9397d5b628ca9b3952492dbc2f51206a7d4c0fb887eb1c7df7b0351c8d81b7e405e527154c896857df9b5e4fde940e2985a9e9b755c36fdabb02d9eca6d42f641fc5c82ea25ef9733af26823b64236c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88988);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224");
  script_bugtraq_id(67899, 67900, 67901);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22590");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco IOS Multiple OpenSSL Vulnerabilities (CSCup22590)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is missing a vendor-supplied security
patch and has an IOS service configured to use TLS or SSL. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that can lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that allows an attacker to
    cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aa6a7e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup22590");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup22590.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

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

ver      = get_kb_item_or_exit("Host/Cisco/IOS/Version");
flag     = 0;
override = TRUE;

if (ver == "12.2(58)EX") flag++;
if (ver == "12.2(58)EY") flag++;
if (ver == "12.2(58)EY1") flag++;
if (ver == "12.2(58)EY2") flag++;
if (ver == "12.2(58)EZ") flag++;
if (ver == "12.2(60)EZ") flag++;
if (ver == "12.2(60)EZ1") flag++;
if (ver == "12.2(60)EZ2") flag++;
if (ver == "12.2(60)EZ3") flag++;
if (ver == "12.2(60)EZ4") flag++;
if (ver == "12.2(60)EZ5") flag++;
if (ver == "12.2(58)SE") flag++;
if (ver == "12.2(58)SE1") flag++;
if (ver == "12.2(58)SE2") flag++;
if (ver == "12.2(54)SG") flag++;
if (ver == "12.2(54)SG1") flag++;
if (ver == "12.2(54)WO") flag++;
if (ver == "12.2(54)XO") flag++;
if (ver == "12.4(22)GC1") flag++;
if (ver == "12.4(24)GC1") flag++;
if (ver == "12.4(24)GC3") flag++;
if (ver == "12.4(24)GC3a") flag++;
if (ver == "12.4(24)GC4") flag++;
if (ver == "12.4(24)GC5") flag++;
if (ver == "12.4(22)MD") flag++;
if (ver == "12.4(22)MD1") flag++;
if (ver == "12.4(22)MD2") flag++;
if (ver == "12.4(24)MD") flag++;
if (ver == "12.4(24)MD1") flag++;
if (ver == "12.4(24)MD2") flag++;
if (ver == "12.4(24)MD3") flag++;
if (ver == "12.4(24)MD4") flag++;
if (ver == "12.4(24)MD5") flag++;
if (ver == "12.4(24)MD6") flag++;
if (ver == "12.4(24)MD7") flag++;
if (ver == "12.4(22)MDA") flag++;
if (ver == "12.4(22)MDA1") flag++;
if (ver == "12.4(22)MDA2") flag++;
if (ver == "12.4(22)MDA3") flag++;
if (ver == "12.4(22)MDA4") flag++;
if (ver == "12.4(22)MDA5") flag++;
if (ver == "12.4(22)MDA6") flag++;
if (ver == "12.4(24)MDA1") flag++;
if (ver == "12.4(24)MDA10") flag++;
if (ver == "12.4(24)MDA11") flag++;
if (ver == "12.4(24)MDA12") flag++;
if (ver == "12.4(24)MDA13") flag++;
if (ver == "12.4(24)MDA2") flag++;
if (ver == "12.4(24)MDA3") flag++;
if (ver == "12.4(24)MDA4") flag++;
if (ver == "12.4(24)MDA5") flag++;
if (ver == "12.4(24)MDA6") flag++;
if (ver == "12.4(24)MDA7") flag++;
if (ver == "12.4(24)MDA8") flag++;
if (ver == "12.4(24)MDA9") flag++;
if (ver == "12.4(24)MDB") flag++;
if (ver == "12.4(24)MDB1") flag++;
if (ver == "12.4(24)MDB10") flag++;
if (ver == "12.4(24)MDB11") flag++;
if (ver == "12.4(24)MDB12") flag++;
if (ver == "12.4(24)MDB13") flag++;
if (ver == "12.4(24)MDB14") flag++;
if (ver == "12.4(24)MDB15") flag++;
if (ver == "12.4(24)MDB16") flag++;
if (ver == "12.4(24)MDB17") flag++;
if (ver == "12.4(24)MDB18") flag++;
if (ver == "12.4(24)MDB19") flag++;
if (ver == "12.4(24)MDB3") flag++;
if (ver == "12.4(24)MDB4") flag++;
if (ver == "12.4(24)MDB5") flag++;
if (ver == "12.4(24)MDB5a") flag++;
if (ver == "12.4(24)MDB6") flag++;
if (ver == "12.4(24)MDB7") flag++;
if (ver == "12.4(24)MDB8") flag++;
if (ver == "12.4(24)MDB9") flag++;
if (ver == "12.4(22)T") flag++;
if (ver == "12.4(22)T1") flag++;
if (ver == "12.4(22)T2") flag++;
if (ver == "12.4(22)T3") flag++;
if (ver == "12.4(22)T4") flag++;
if (ver == "12.4(22)T5") flag++;
if (ver == "12.4(24)T") flag++;
if (ver == "12.4(24)T1") flag++;
if (ver == "12.4(24)T2") flag++;
if (ver == "12.4(24)T3") flag++;
if (ver == "12.4(24)T3e") flag++;
if (ver == "12.4(24)T3f") flag++;
if (ver == "12.4(24)T4") flag++;
if (ver == "12.4(24)T4a") flag++;
if (ver == "12.4(24)T4b") flag++;
if (ver == "12.4(24)T4c") flag++;
if (ver == "12.4(24)T4d") flag++;
if (ver == "12.4(24)T4e") flag++;
if (ver == "12.4(24)T4f") flag++;
if (ver == "12.4(24)T4l") flag++;
if (ver == "12.4(24)T5") flag++;
if (ver == "12.4(24)T6") flag++;
if (ver == "12.4(24)T7") flag++;
if (ver == "12.4(24)T8") flag++;
if (ver == "12.4(22)XR1") flag++;
if (ver == "12.4(22)XR10") flag++;
if (ver == "12.4(22)XR11") flag++;
if (ver == "12.4(22)XR12") flag++;
if (ver == "12.4(22)XR2") flag++;
if (ver == "12.4(22)XR3") flag++;
if (ver == "12.4(22)XR4") flag++;
if (ver == "12.4(22)XR5") flag++;
if (ver == "12.4(22)XR6") flag++;
if (ver == "12.4(22)XR7") flag++;
if (ver == "12.4(22)XR8") flag++;
if (ver == "12.4(22)XR9") flag++;
if (ver == "12.4(22)YD") flag++;
if (ver == "12.4(22)YD1") flag++;
if (ver == "12.4(22)YD2") flag++;
if (ver == "12.4(22)YD3") flag++;
if (ver == "12.4(22)YD4") flag++;
if (ver == "12.4(22)YE2") flag++;
if (ver == "12.4(22)YE3") flag++;
if (ver == "12.4(22)YE4") flag++;
if (ver == "12.4(22)YE5") flag++;
if (ver == "12.4(22)YE6") flag++;
if (ver == "12.4(24)YE") flag++;
if (ver == "12.4(24)YE1") flag++;
if (ver == "12.4(24)YE2") flag++;
if (ver == "12.4(24)YE3") flag++;
if (ver == "12.4(24)YE3a") flag++;
if (ver == "12.4(24)YE3b") flag++;
if (ver == "12.4(24)YE3c") flag++;
if (ver == "12.4(24)YE3d") flag++;
if (ver == "12.4(24)YE3e") flag++;
if (ver == "12.4(24)YE4") flag++;
if (ver == "12.4(24)YE5") flag++;
if (ver == "12.4(24)YE6") flag++;
if (ver == "12.4(24)YE7") flag++;
if (ver == "12.4(24)YG1") flag++;
if (ver == "12.4(24)YG2") flag++;
if (ver == "12.4(24)YG3") flag++;
if (ver == "12.4(24)YG4") flag++;
if (ver == "15.0(2)EB") flag++;
if (ver == "15.0(2)EC") flag++;
if (ver == "15.0(2)ED") flag++;
if (ver == "15.0(2)ED1") flag++;
if (ver == "15.0(2)EH") flag++;
if (ver == "15.0(2)EJ") flag++;
if (ver == "15.0(2)EJ1") flag++;
if (ver == "15.0(2)EK") flag++;
if (ver == "15.0(2)EK1") flag++;
if (ver == "15.0(1)EX") flag++;
if (ver == "15.0(2)EX") flag++;
if (ver == "15.0(2)EX1") flag++;
if (ver == "15.0(2)EX2") flag++;
if (ver == "15.0(2)EX3") flag++;
if (ver == "15.0(2)EX4") flag++;
if (ver == "15.0(2)EX5") flag++;
if (ver == "15.0(1)EY") flag++;
if (ver == "15.0(1)EY1") flag++;
if (ver == "15.0(1)EY2") flag++;
if (ver == "15.0(2)EY") flag++;
if (ver == "15.0(2)EY1") flag++;
if (ver == "15.0(2)EY2") flag++;
if (ver == "15.0(2)EY3") flag++;
if (ver == "15.0(2)EZ") flag++;
if (ver == "15.0(1)M") flag++;
if (ver == "15.0(1)M1") flag++;
if (ver == "15.0(1)M10") flag++;
if (ver == "15.0(1)M2") flag++;
if (ver == "15.0(1)M3") flag++;
if (ver == "15.0(1)M4") flag++;
if (ver == "15.0(1)M5") flag++;
if (ver == "15.0(1)M6") flag++;
if (ver == "15.0(1)M7") flag++;
if (ver == "15.0(1)M8") flag++;
if (ver == "15.0(1)M9") flag++;
if (ver == "15.0(1)MR") flag++;
if (ver == "15.0(2)MR") flag++;
if (ver == "15.0(1)S2") flag++;
if (ver == "15.0(1)S5") flag++;
if (ver == "15.0(1)S6") flag++;
if (ver == "15.0(1)SE") flag++;
if (ver == "15.0(1)SE1") flag++;
if (ver == "15.0(1)SE2") flag++;
if (ver == "15.0(1)SE3") flag++;
if (ver == "15.0(2)SE") flag++;
if (ver == "15.0(2)SE1") flag++;
if (ver == "15.0(2)SE2") flag++;
if (ver == "15.0(2)SE3") flag++;
if (ver == "15.0(2)SE4") flag++;
if (ver == "15.0(2)SE5") flag++;
if (ver == "15.0(2)SE6") flag++;
if (ver == "15.0(2)SG") flag++;
if (ver == "15.0(2)SG1") flag++;
if (ver == "15.0(2)SG2") flag++;
if (ver == "15.0(2)SG3") flag++;
if (ver == "15.0(2)SG4") flag++;
if (ver == "15.0(2)SG5") flag++;
if (ver == "15.0(2)SG6") flag++;
if (ver == "15.0(2)SG7") flag++;
if (ver == "15.0(2)SG8") flag++;
if (ver == "15.0(1)XA") flag++;
if (ver == "15.0(1)XA1") flag++;
if (ver == "15.0(1)XA2") flag++;
if (ver == "15.0(1)XA3") flag++;
if (ver == "15.0(1)XA4") flag++;
if (ver == "15.0(1)XA5") flag++;
if (ver == "15.0(1)XO") flag++;
if (ver == "15.0(1)XO1") flag++;
if (ver == "15.0(2)XO") flag++;
if (ver == "15.1(2)EY") flag++;
if (ver == "15.1(2)EY1a") flag++;
if (ver == "15.1(2)EY2") flag++;
if (ver == "15.1(2)EY2a") flag++;
if (ver == "15.1(2)EY3") flag++;
if (ver == "15.1(2)EY4") flag++;
if (ver == "15.1(2)GC") flag++;
if (ver == "15.1(2)GC1") flag++;
if (ver == "15.1(2)GC2") flag++;
if (ver == "15.1(4)GC") flag++;
if (ver == "15.1(4)GC1") flag++;
if (ver == "15.1(4)GC2") flag++;
if (ver == "15.1(4)M") flag++;
if (ver == "15.1(4)M1") flag++;
if (ver == "15.1(4)M2") flag++;
if (ver == "15.1(4)M3") flag++;
if (ver == "15.1(4)M3a") flag++;
if (ver == "15.1(4)M4") flag++;
if (ver == "15.1(4)M5") flag++;
if (ver == "15.1(4)M6") flag++;
if (ver == "15.1(4)M7") flag++;
if (ver == "15.1(4)M8") flag++;
if (ver == "15.1(1)MR") flag++;
if (ver == "15.1(1)MR1") flag++;
if (ver == "15.1(1)MR2") flag++;
if (ver == "15.1(1)MR3") flag++;
if (ver == "15.1(1)MR4") flag++;
if (ver == "15.1(3)MR") flag++;
if (ver == "15.1(3)MRA") flag++;
if (ver == "15.1(3)MRA1") flag++;
if (ver == "15.1(3)MRA2") flag++;
if (ver == "15.1(3)MRA3") flag++;
if (ver == "15.1(3)MRA4") flag++;
if (ver == "15.1(1)S") flag++;
if (ver == "15.1(1)S1") flag++;
if (ver == "15.1(1)S2") flag++;
if (ver == "15.1(2)S") flag++;
if (ver == "15.1(2)S1") flag++;
if (ver == "15.1(2)S2") flag++;
if (ver == "15.1(3)S") flag++;
if (ver == "15.1(3)S0a") flag++;
if (ver == "15.1(3)S1") flag++;
if (ver == "15.1(3)S2") flag++;
if (ver == "15.1(3)S3") flag++;
if (ver == "15.1(3)S4") flag++;
if (ver == "15.1(3)S5") flag++;
if (ver == "15.1(3)S5a") flag++;
if (ver == "15.1(3)S6") flag++;
if (ver == "15.1(1)SG") flag++;
if (ver == "15.1(1)SG1") flag++;
if (ver == "15.1(1)SG2") flag++;
if (ver == "15.1(2)SG") flag++;
if (ver == "15.1(2)SG1") flag++;
if (ver == "15.1(2)SG2") flag++;
if (ver == "15.1(2)SG3") flag++;
if (ver == "15.1(2)SG4") flag++;
if (ver == "15.1(2)SNG") flag++;
if (ver == "15.1(2)SNH") flag++;
if (ver == "15.1(2)SNI") flag++;
if (ver == "15.1(2)SNI1") flag++;
if (ver == "15.1(3)SVB1") flag++;
if (ver == "15.1(3)SVD") flag++;
if (ver == "15.1(3)SVD1") flag++;
if (ver == "15.1(3)SVD2") flag++;
if (ver == "15.1(3)SVE") flag++;
if (ver == "15.1(3)SVF") flag++;
if (ver == "15.1(3)SVF1") flag++;
if (ver == "15.1(3)SVF4a") flag++;
if (ver == "15.1(1)SY") flag++;
if (ver == "15.1(1)SY1") flag++;
if (ver == "15.1(1)SY2") flag++;
if (ver == "15.1(1)SY3") flag++;
if (ver == "15.1(2)SY") flag++;
if (ver == "15.1(2)SY1") flag++;
if (ver == "15.1(2)SY2") flag++;
if (ver == "15.1(2)SY3") flag++;
if (ver == "15.1(1)T") flag++;
if (ver == "15.1(1)T1") flag++;
if (ver == "15.1(1)T2") flag++;
if (ver == "15.1(1)T3") flag++;
if (ver == "15.1(1)T4") flag++;
if (ver == "15.1(1)T5") flag++;
if (ver == "15.1(2)T") flag++;
if (ver == "15.1(2)T0a") flag++;
if (ver == "15.1(2)T1") flag++;
if (ver == "15.1(2)T2") flag++;
if (ver == "15.1(2)T2a") flag++;
if (ver == "15.1(2)T3") flag++;
if (ver == "15.1(2)T4") flag++;
if (ver == "15.1(2)T5") flag++;
if (ver == "15.1(3)T") flag++;
if (ver == "15.1(3)T1") flag++;
if (ver == "15.1(3)T2") flag++;
if (ver == "15.1(3)T3") flag++;
if (ver == "15.1(3)T4") flag++;
if (ver == "15.1(1)XB") flag++;
if (ver == "15.2(1)E") flag++;
if (ver == "15.2(1)E1") flag++;
if (ver == "15.2(1)E2") flag++;
if (ver == "15.2(1)E3") flag++;
if (ver == "15.2(2)E") flag++;
if (ver == "15.2(1)EY") flag++;
if (ver == "15.2(1)GC") flag++;
if (ver == "15.2(1)GC1") flag++;
if (ver == "15.2(1)GC2") flag++;
if (ver == "15.2(2)GC") flag++;
if (ver == "15.2(3)GC") flag++;
if (ver == "15.2(3)GC1") flag++;
if (ver == "15.2(4)GC") flag++;
if (ver == "15.2(4)GC1") flag++;
if (ver == "15.2(4)GC2") flag++;
if (ver == "15.2(2)JA") flag++;
if (ver == "15.2(2)JA1") flag++;
if (ver == "15.2(4)JA") flag++;
if (ver == "15.2(4)JA1") flag++;
if (ver == "15.2(2)JAX") flag++;
if (ver == "15.2(2)JAX1") flag++;
if (ver == "15.2(2)JB") flag++;
if (ver == "15.2(2)JB1") flag++;
if (ver == "15.2(2)JB2") flag++;
if (ver == "15.2(2)JB3") flag++;
if (ver == "15.2(4)JB") flag++;
if (ver == "15.2(4)JB1") flag++;
if (ver == "15.2(4)JB2") flag++;
if (ver == "15.2(4)JB3") flag++;
if (ver == "15.2(4)JB3a") flag++;
if (ver == "15.2(4)JB3b") flag++;
if (ver == "15.2(4)JB3h") flag++;
if (ver == "15.2(4)JB3s") flag++;
if (ver == "15.2(4)JB4") flag++;
if (ver == "15.2(4)JB5") flag++;
if (ver == "15.2(4)JB5h") flag++;
if (ver == "15.2(4)JB5m") flag++;
if (ver == "15.2(4)JB50") flag++;
if (ver == "15.2(2)JN1") flag++;
if (ver == "15.2(2)JN2") flag++;
if (ver == "15.2(4)JN") flag++;
if (ver == "15.2(4)M") flag++;
if (ver == "15.2(4)M1") flag++;
if (ver == "15.2(4)M2") flag++;
if (ver == "15.2(4)M3") flag++;
if (ver == "15.2(4)M4") flag++;
if (ver == "15.2(4)M5") flag++;
if (ver == "15.2(4)M6") flag++;
if (ver == "15.2(4)M6a") flag++;
if (ver == "15.2(1)S") flag++;
if (ver == "15.2(1)S1") flag++;
if (ver == "15.2(1)S2") flag++;
if (ver == "15.2(2)S") flag++;
if (ver == "15.2(2)S0a") flag++;
if (ver == "15.2(2)S0c") flag++;
if (ver == "15.2(2)S1") flag++;
if (ver == "15.2(2)S2") flag++;
if (ver == "15.2(4)S") flag++;
if (ver == "15.2(4)S1") flag++;
if (ver == "15.2(4)S2") flag++;
if (ver == "15.2(4)S3") flag++;
if (ver == "15.2(4)S3a") flag++;
if (ver == "15.2(4)S4") flag++;
if (ver == "15.2(4)S4a") flag++;
if (ver == "15.2(4)S5") flag++;
if (ver == "15.2(2)SNG") flag++;
if (ver == "15.2(2)SNH1") flag++;
if (ver == "15.2(2)SNI") flag++;
if (ver == "15.2(1)T") flag++;
if (ver == "15.2(1)T1") flag++;
if (ver == "15.2(1)T2") flag++;
if (ver == "15.2(1)T3") flag++;
if (ver == "15.2(1)T3a") flag++;
if (ver == "15.2(1)T4") flag++;
if (ver == "15.2(2)T") flag++;
if (ver == "15.2(2)T1") flag++;
if (ver == "15.2(2)T2") flag++;
if (ver == "15.2(2)T3") flag++;
if (ver == "15.2(2)T4") flag++;
if (ver == "15.2(3)T") flag++;
if (ver == "15.2(3)T1") flag++;
if (ver == "15.2(3)T2") flag++;
if (ver == "15.2(3)T3") flag++;
if (ver == "15.2(3)T4") flag++;
if (ver == "15.3(3)JN") flag++;
if (ver == "15.3(3)M") flag++;
if (ver == "15.3(3)M1") flag++;
if (ver == "15.3(3)M2") flag++;
if (ver == "15.3(3)M3") flag++;
if (ver == "15.3(1)S") flag++;
if (ver == "15.3(1)S1") flag++;
if (ver == "15.3(1)S2") flag++;
if (ver == "15.3(2)S") flag++;
if (ver == "15.3(2)S0a") flag++;
if (ver == "15.3(2)S1") flag++;
if (ver == "15.3(2)S2") flag++;
if (ver == "15.3(3)S") flag++;
if (ver == "15.3(3)S1") flag++;
if (ver == "15.3(3)S1a") flag++;
if (ver == "15.3(3)S2") flag++;
if (ver == "15.3(3)S3") flag++;
if (ver == "15.3(1)T") flag++;
if (ver == "15.3(1)T1") flag++;
if (ver == "15.3(1)T2") flag++;
if (ver == "15.3(1)T3") flag++;
if (ver == "15.3(1)T4") flag++;
if (ver == "15.3(2)T") flag++;
if (ver == "15.3(2)T1") flag++;
if (ver == "15.3(2)T2") flag++;
if (ver == "15.3(2)T3") flag++;
if (ver == "15.4(1)CG") flag++;
if (ver == "15.4(1)CG1") flag++;
if (ver == "15.4(2)CG") flag++;
if (ver == "15.4(1)S") flag++;
if (ver == "15.4(1)S1") flag++;
if (ver == "15.4(1)S2") flag++;
if (ver == "15.4(2)S") flag++;
if (ver == "15.4(1)T") flag++;
if (ver == "15.4(1)T1") flag++;
if (ver == "15.4(2)T") flag++;
if (ver == "15.4(2)T1") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS", ver);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all", "show running-config all");

  if (check_cisco_result(buf))
  {
    override = FALSE;

    if (
      # Web UI HTTPS
      preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE) ||
      # SSL VPN
      cisco_check_sections(
        config:buf,
        section_regex:"^webvpn gateway ",
        config_regex:'^\\s*inservice'
      ) ||
      # HTTPS client feature / Voice-XML HTTPS client
      preg(string:buf, pattern:"^(ip )?http client secure-", multiline:TRUE) ||
      # CNS feature
      preg(string:buf, pattern:"^cns (config|exec|event) .* encrypt", multiline:TRUE) ||
      # Settlement for Packet Telephony feature
      cisco_check_sections(
        config:buf,
        section_regex:"^settlement ",
        config_regex:make_list('^\\s*url https:', '^\\s*no shutdown')
      ) ||
      # CMTS billing feature
      preg(string:buf, pattern:"^cable metering .* secure", multiline:TRUE)
    ) flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override = TRUE;
  }

  if (!flag) audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup22590' +
    '\n  Installed release : ' + ver +
    '\n';
  security_warning(port:0, extra:report + cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
