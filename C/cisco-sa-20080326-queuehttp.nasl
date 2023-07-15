#TRUSTED 9acd0782352b9cd55c7f0cc94bab1b2eb54087bc840ec8c622260465c258eb8045aba477b3d079117970619bf215cd51748ec3a98a3adc207103731a9affa68272e591633b58b0e74afef28cf444afa9fdab7985bdd5f23cd5be34771ea85f24023b286cb02431dd7215d79d44d01642d7763204e8dfad33840b8d689608e8aac17fe601d1663d883024ea022e2ac7d3ac74391716a2f93eb74a615ad14b863feb912096fe00d2348af14badf7d78bc356af418ae72aada9897671ec5764353e77573b97061feecdc5808cf020110d60718ddc7aad4d19baa6ff72220b6722427697832cd80daf565300840e7f5b267ba45e7d1631adf9b4f23b4793b84424b46f32aed2c633c7e29a1f15464e1917a775492a3f32659123d39daa513129cca17bb94189638119e2386829fd6ef892382b7c58fb6d3a284768b5b4dac1504de5e42041485e5ecd64e947495180cabb678e9d79e48f76c198342b87fd242e517ca86df97c9f111a54e18fcfaf2d279284d828d968f7f6ec8498fee03dd133ce7a44e537bee9af3d5f35ed775ec6d0ae8d400c02d1c5b5354f5431501008779407389cecc37f0c2071189e9476a20be10a1a4405ab38969a24369d2be015f2e9773982907bdf2634835479a73e0a91f96c2ae8d270a6843255c280ca914b5dd84ba37c399f09b4e9e4d884fb4d8b1b4bb6654685740f93082cfbbac72cc61fcda3
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080969882.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49014);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-0537");
 script_bugtraq_id(28463);
 script_name(english:"Vulnerability in Cisco IOS with OSPF, MPLS VPN, and Supervisor 32, Supervisor 720, or Route Switch Processor 720");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Certain Cisco Catalyst 6500 Series and Cisco 7600 Router devices that
run branches of Cisco IOS based on 12.2 can be vulnerable to a denial
of service vulnerability that can prevent any traffic from entering an
affected interface. For a device to be vulnerable, it must be
configured for Open Shortest Path First (OSPF) Sham-Link and Multi
Protocol Label Switching (MPLS) Virtual Private Networking (VPN). This
vulnerability only affects Cisco Catalyst 6500 Series or Catalyst 7600
Series devices with the Supervisor Engine 32 (Sup32), Supervisor Engine
720 (Sup720) or Route Switch Processor 720 (RSP720) modules. The
Supervisor 32, Supervisor 720, Supervisor 720-3B, Supervisor 720-3BXL,
Route Switch Processor 720, Route Switch Processor 720-3C, and Route
Switch Processor 720-3CXL are all potentially vulnerable.
 OSPF and MPLS VPNs are not enabled by default.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0983c385");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080969882.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c0565f82");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080326-queue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/26");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsf12082");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080326-queue");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.2(18)ZU2') flag++;
else if (version == '12.2(18)ZU1') flag++;
else if (version == '12.2(18)ZU') flag++;
else if (version == '12.2(18)SXF5') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
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
else if (version == '12.2(18)SXD7b') flag++;
else if (version == '12.2(18)SXD7a') flag++;
else if (version == '12.2(18)SXD7') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;
else if (version == '12.2(17d)SXB9') flag++;
else if (version == '12.2(17d)SXB8') flag++;
else if (version == '12.2(17d)SXB7') flag++;
else if (version == '12.2(17d)SXB6') flag++;
else if (version == '12.2(17d)SXB5') flag++;
else if (version == '12.2(17d)SXB4') flag++;
else if (version == '12.2(17d)SXB3') flag++;
else if (version == '12.2(17d)SXB2') flag++;
else if (version == '12.2(17d)SXB11a') flag++;
else if (version == '12.2(17d)SXB11') flag++;
else if (version == '12.2(17d)SXB10') flag++;
else if (version == '12.2(17d)SXB1') flag++;
else if (version == '12.2(17d)SXB') flag++;
else if (version == '12.2(17b)SXA2') flag++;
else if (version == '12.2(17b)SXA') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(18)IXE') flag++;
else if (version == '12.2(18)IXD1') flag++;
else if (version == '12.2(18)IXD') flag++;
else if (version == '12.2(18)IXC') flag++;
else if (version == '12.2(18)IXB2') flag++;
else if (version == '12.2(18)IXB1') flag++;
else if (version == '12.2(18)IXB') flag++;
else if (version == '12.2(18)IXA') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"sham-link", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"address-family vpnv4", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
