#TRUSTED a9c9914885a3b2aa59a86b8c90d84801c1868436588b3238cbf9305eaf4a98e25b776c543de82f53082f659217c1aa7d0d434b800001e49261abc7cbf1731790f174aa7d9cfd4ef495753ca5248eb4f0f5ed07c4cb907048ee99a7f4a934772c2c1ade04e48d59bdfab32f90259b96b33caebe9a5b1ddd593fbdca010f9e0c05b73651198968d22a4005a17d790f76f76075d0e6ece6444e457aa45591de0c89e80e9377357164516045c2660495bb68d4a872fe6a9bcc4f6b9c8844ef78c8103293be7f435fdf093decd3bd6575b112afb02024aaf6d252e7dc0f04b55568e2073f5c84a77d87752077917b783d51d3da2d16cbb55dfe273e23e02c67a610c31ec806310d11739a10d01c9e9b1170404db03ce62ad5c6b1d589ec7bfc4097e581e1182539acd3fe8f74d6095d778e9a085ff13d3399c51a40a9f0c15d84a5afa39ffbbebef0f0c62956cd012e5581957856f66a3dfb1ba53d91bac60d09986d1d1e44cd2245432099b84d8340b09d17cda27c99a68c8a4e2db626ebb4d9291fdd50ef0676c42052a00438e21c3b81ff4ba44ee81d063ff6bd049e40db295c68cdb90500f608578f2a915a6483fef2b826fa4bb382980e1d30e2464960aafeeea2548bbf4bf332f6d5c40a6d80266c7229d96a3e8acc2ecc42e45ddde927bdd7bb2f56ccc320247167fbdae9400bccf35880cf8fd1a1d2d38b29995244b8f304
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ac.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49022);
 script_version("1.21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-3804");
 script_bugtraq_id(31360);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk93241");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-mfi");
 script_name(english:"Cisco IOS MPLS Forwarding Infrastructure Denial of Service Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software Multi Protocol Label Switching (MPLS) Forwarding
Infrastructure (MFI) is vulnerable to a denial of service (DoS) attack
from specially crafted packets. Only the MFI is affected by this
vulnerability. Older Label Forwarding Information Base (LFIB)
implementation, which is replaced by MFI, is not affected.

 Cisco has released free software updates that address this
vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d19523c4");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ac.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?24c66685");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-mfi.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
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

if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.2(28)ZX') flag++;
else if (version == '12.2(33)XN1') flag++;
else if (version == '12.2(33)SXH2a') flag++;
else if (version == '12.2(33)SXH2') flag++;
else if (version == '12.2(33)SXH1') flag++;
else if (version == '12.2(33)SXH') flag++;
else if (version == '12.2(25)SW3a') flag++;
else if (version == '12.2(25)SW11') flag++;
else if (version == '12.2(29)SVE0') flag++;
else if (version == '12.2(29)SVD1') flag++;
else if (version == '12.2(29)SVD0') flag++;
else if (version == '12.2(29)SVD') flag++;
else if (version == '12.2(29)SVC') flag++;
else if (version == '12.2(29)SVA2') flag++;
else if (version == '12.2(29b)SV1') flag++;
else if (version == '12.2(29b)SV') flag++;
else if (version == '12.2(29a)SV1') flag++;
else if (version == '12.2(29a)SV') flag++;
else if (version == '12.2(29)SV3') flag++;
else if (version == '12.2(28)SV2') flag++;
else if (version == '12.2(28)SV1') flag++;
else if (version == '12.2(28)SV') flag++;
else if (version == '12.2(27)SV5') flag++;
else if (version == '12.2(27)SV4') flag++;
else if (version == '12.2(27)SV3') flag++;
else if (version == '12.2(27)SV2') flag++;
else if (version == '12.2(27)SV1') flag++;
else if (version == '12.2(27)SV') flag++;
else if (version == '12.2(25)SV2') flag++;
else if (version == '12.2(24)SV1') flag++;
else if (version == '12.2(23)SV1') flag++;
else if (version == '12.2(22)SV1') flag++;
else if (version == '12.2(33)SRC') flag++;
else if (version == '12.2(33)SRB3') flag++;
else if (version == '12.2(33)SRB2') flag++;
else if (version == '12.2(33)SRB1') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(33)SRA7') flag++;
else if (version == '12.2(33)SRA6') flag++;
else if (version == '12.2(33)SRA5') flag++;
else if (version == '12.2(33)SRA4') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(37)SG1') flag++;
else if (version == '12.2(31)SG2') flag++;
else if (version == '12.2(25)SEG3') flag++;
else if (version == '12.2(25)SEG1') flag++;
else if (version == '12.2(25)SEG') flag++;
else if (version == '12.2(25)SEE4') flag++;
else if (version == '12.2(25)SEE') flag++;
else if (version == '12.2(25)SED1') flag++;
else if (version == '12.2(25)SED') flag++;
else if (version == '12.2(44)SE2') flag++;
else if (version == '12.2(44)SE1') flag++;
else if (version == '12.2(44)SE') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(37)SE1') flag++;
else if (version == '12.2(37)SE') flag++;
else if (version == '12.2(35)SE5') flag++;
else if (version == '12.2(35)SE2') flag++;
else if (version == '12.2(35)SE1') flag++;
else if (version == '12.2(33)SCA') flag++;
else if (version == '12.2(27)SBC5') flag++;
else if (version == '12.2(27)SBC4') flag++;
else if (version == '12.2(27)SBC3') flag++;
else if (version == '12.2(27)SBC2') flag++;
else if (version == '12.2(27)SBC1') flag++;
else if (version == '12.2(27)SBC') flag++;
else if (version == '12.2(27)SBB4e') flag++;
else if (version == '12.2(31)SB9') flag++;
else if (version == '12.2(31)SB8') flag++;
else if (version == '12.2(31)SB7') flag++;
else if (version == '12.2(31)SB6') flag++;
else if (version == '12.2(31)SB5') flag++;
else if (version == '12.2(31)SB3x') flag++;
else if (version == '12.2(31)SB3') flag++;
else if (version == '12.2(31)SB2') flag++;
else if (version == '12.2(31)SB11') flag++;
else if (version == '12.2(31)SB10') flag++;
else if (version == '12.2(28)SB9') flag++;
else if (version == '12.2(28)SB8') flag++;
else if (version == '12.2(28)SB7') flag++;
else if (version == '12.2(28)SB6') flag++;
else if (version == '12.2(28)SB5c') flag++;
else if (version == '12.2(28)SB5') flag++;
else if (version == '12.2(28)SB4d') flag++;
else if (version == '12.2(28)SB4') flag++;
else if (version == '12.2(28)SB3') flag++;
else if (version == '12.2(28)SB2') flag++;
else if (version == '12.2(28)SB12') flag++;
else if (version == '12.2(28)SB11') flag++;
else if (version == '12.2(28)SB10') flag++;
else if (version == '12.2(28)SB1') flag++;
else if (version == '12.2(28)SB') flag++;
else if (version == '12.2(25)S9') flag++;
else if (version == '12.2(25)S8') flag++;
else if (version == '12.2(25)S7') flag++;
else if (version == '12.2(25)S6') flag++;
else if (version == '12.2(25)S5') flag++;
else if (version == '12.2(25)S4') flag++;
else if (version == '12.2(25)S3') flag++;
else if (version == '12.2(25)S2') flag++;
else if (version == '12.2(25)S15') flag++;
else if (version == '12.2(25)S14') flag++;
else if (version == '12.2(25)S13') flag++;
else if (version == '12.2(25)S12') flag++;
else if (version == '12.2(25)S11') flag++;
else if (version == '12.2(25)S10') flag++;
else if (version == '12.2(25)S1') flag++;
else if (version == '12.2(25)S') flag++;
else if (version == '12.2(22)S2') flag++;
else if (version == '12.2(22)S1') flag++;
else if (version == '12.2(22)S') flag++;
else if (version == '12.2(33)IRA') flag++;
else if (version == '12.2(25)EY4') flag++;
else if (version == '12.2(25)EY3') flag++;
else if (version == '12.2(25)EY2') flag++;
else if (version == '12.2(25)EY1') flag++;
else if (version == '12.2(25)EY') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys_name_mfi_ios", "show subsys name mfi_ios");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"mfi_ios\s+Protocol", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_mpls_interface", "show mpls interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Interface", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
