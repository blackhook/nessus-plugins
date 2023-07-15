#TRUSTED 892563a9b774d7a4ed33fd87d6288ad1afcd6f126a092df63913f05783e0276b9479a5c56b38eefd15a94ed25e78636332c551cdf1d26d5c2c4d3eca10d740c57aa0b51badcfacea745ff8dc600f756d26edf4c0f274e711d2368d0277a491343276178d298a859aaba6ca4ab1762ec8f870bf1990b1de6bd5998633a758772aa6f7866c94a42344ac06aa155cc32e36805e3336078efb7a73317e294e97063541eb13683b2dc5f65cc8a7d1ce6b26fd93e7050a1695566d0c1f7e3fdd0f103c87436582b60a7e63da5857212d0174d6098aa282f0e1756633aaf89abc895b3594f58ee80fd660bb965c6f16a492edbb42ca106612f9ede1edd68de06c97c9591df6a6d115528ccf1edfb6c290e71b6f9207dc9e96b97783486f7098b0d8248918433ae4a3084dc3035c11970697e40ffaa276c98bb76cfa41a597672090c95bb39ca9a5503d11064edfbbbe5ff369ffea5675c474d466251916a7417bd37004a314ed28e6018efba2ab2d6496b511c9cb8363b8326894f4b9e133e2034ea7e1312149a1240229412225c1e8b91a52dccd5617e01e335ab6c67315622495170c4badbea41c02ff616b3bdd777aeefd1d4b1ad307e0311b9e6b13e29f281449385da0f75ca794d61966a24adee888f3622eded180f9286e790f6b943e85cbbe44d0435f925b6638941b77842520c6a5030f729b2ae11770734d928b62a2bc7f63
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00807f413e.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49001);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2007-1258");
 script_name(english:"Cisco Catalyst 6000, 6500 and Cisco 7600 Series MPLS Packet Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Catalyst 6500 series systems that are running certain versions of
Cisco Internetwork Operating System (IOS) are vulnerable to an attack
from a Multi Protocol Label Switching (MPLS) packet. Only the systems
that are running in Hybrid Mode (Catalyst OS (CatOS) software on the
Supervisor Engine and IOS Software on the Multilayer Switch Feature
Card (MSFC)) or running with Cisco IOS Software Modularity are
affected.
MPLS packets can only be sent from the local network segment.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99a010c1");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00807f413e.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?08e188df");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070228-mpls.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCef90002");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd37415");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070228-mpls");
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

if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(17d)SXB4') flag++;
else if (version == '12.2(17d)SXB3') flag++;
else if (version == '12.2(17d)SXB2') flag++;
else if (version == '12.2(17d)SXB1') flag++;
else if (version == '12.2(17b)SXA2') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"s72033-adventerprisek9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-advipservicesk9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-entservicesk9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-ipservices_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-ipservicesk9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-ipservicesk9-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
