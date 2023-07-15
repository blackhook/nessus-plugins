#TRUSTED 0b690d01d3d85af3540d2bee964d91d56821fe9d896db6f52a26ad069c64d92ef515c45ead925186e73b9e05e6808a3ad9d3ab440e6c42f1ad724d8e5f975717a06c57fd9264ad5ff6dba16ac454630ee9290e443106db66339a49a9ed142a65b2015ea593e12ab7f9a6c37c9d67046d53d9a8d22c93bcd6ab4dfdccc27cadc5db6707b83507d8404239a9bd87da1edef3a936bff4f3db8a00c49366c51247f0d7218746ce1e2d6366a307356aef6d6aeba7f2c3d6ef718b3972ff2f4647f980f41c981d81ef7fc0dac958865e0a6a70b2ff3ff7b7cc207712fcd5ce249d983cde6db5739d68181a53794b974b44b92259afd88a9e53473cc24c2f96dc5e514b8f848ec443793a3ce0d05975fd5f27a980b73d8a30bd941b7e48d7f4bcdcde97fa93f7a22334f683f74945ec43287729cba1aa961d3f21b184b66651429df28e2925c2966a64563797cd81cb482b785a9237cd156135832eed98f4bdba051aa9a254f159e1da7cca7e44fe087289f79a74f81089cafcf4dfc1010123325c7f190d96a65d132cfc4c7dcf053a4b74aee287c361067191f7b7371045c12a959ea879313cd391825bf42f7303ea1aaec8687e7683c62322245b8bbd8c78929fc2281a4ed7e9de64f1cc8e28a4743889c1212e3163d0d5b76b8207636c413783acdf348db995280bc6d1b50fe46d41990cdcff6485949fcfaf4541d3f796f4cf02b7
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080b95d57.shtml

include("compat.inc");

if (description)
{
 script_id(56321);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2011-3273", "CVE-2011-3281");
 script_bugtraq_id(49826);
 script_xref(name:"CISCO-BUG-ID", value:"CSCti79848");
 script_xref(name:"CISCO-BUG-ID", value:"CSCto68554");
 script_xref(name:"CISCO-BUG-ID", value:"CSCtq28732");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-zbfw");

 script_name(english:"Cisco IOS Software IPS and Zone-Based Firewall Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco IOS Software contains two vulnerabilities related to Cisco IOS
Intrusion Prevention System (IPS) and Cisco IOS Zone-Based Firewall
features. These vulnerabilities are :

  - Memory leak

  - Denial of service caused by processing specially
    crafted HTTP packets

Cisco has released free software updates that address these
vulnerabilities. Workarounds that mitigate these vulnerabilities are
not available.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adac0917");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080b95d57.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4f83d3b");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-zbfw.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/29");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/09/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2011-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");

 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '15.1(4)XB4') flag++;
else if (version == '15.1(1)XB') flag++;
else if (version == '15.1(3)T1') flag++;
else if (version == '15.1(3)T') flag++;
else if (version == '15.1(2)T3') flag++;
else if (version == '15.1(2)T2a') flag++;
else if (version == '15.1(2)T2') flag++;
else if (version == '15.1(2)T1') flag++;
else if (version == '15.1(2)T0a') flag++;
else if (version == '15.1(2)T') flag++;
else if (version == '15.1(1)T3') flag++;
else if (version == '15.1(1)T2') flag++;
else if (version == '15.1(1)T1') flag++;
else if (version == '15.1(1)T') flag++;
else if (version == '15.1(4)M0b') flag++;
else if (version == '15.1(4)M0a') flag++;
else if (version == '15.1(4)M') flag++;
else if (version == '15.1(2)GC1') flag++;
else if (version == '15.1(2)GC') flag++;
else if (version == '15.0(1)XA5') flag++;
else if (version == '15.0(1)XA4') flag++;
else if (version == '15.0(1)XA3') flag++;
else if (version == '15.0(1)XA2') flag++;
else if (version == '15.0(1)XA1') flag++;
else if (version == '15.0(1)XA') flag++;
else if (version == '15.0(1)M6') flag++;
else if (version == '15.0(1)M5') flag++;
else if (version == '15.0(1)M4') flag++;
else if (version == '15.0(1)M3') flag++;
else if (version == '15.0(1)M2') flag++;
else if (version == '15.0(1)M1') flag++;
else if (version == '15.0(1)M') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ips_interfaces", "show ip ips interfaces");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"IPS rule", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
