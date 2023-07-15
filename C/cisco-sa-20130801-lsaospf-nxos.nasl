#TRUSTED 02c3e6dd3e3efbaf9925205103a55ef76604d3e5912521e764dc44ee5ce41fca6b8b369a9332a4d828e57f2047c04a5232fb7f8d323dbc37038b52923f5800a6c1219f44acc73b23fbb58bb579b73588fc495bb7077a7bf9597616d41807dbc6ac2df57f9199701d377e0e568a2e95bc9717bb08d876648a9898738574aaf66274ccfe2515d281bcb3d56c7f3556837ab212f5e76809443264c7372b5fb06ebe9f0eb66cc8e941c27a555ab77c0198ef753e78a374e944ace980127d0a0a15b1e3d0d98bbb3cf73b248cd509c0bbb15f46529266f095ad4bdc380fb935fe3173d87ef1141bd5eafa1bc227e8e7007627879ec151db54a09802da50efed14daf89dae63b7da968722f51dc23c80ee51f1e9069b821f3d26d923d984e16575fba025a47c3316bf9ff17edd5eccb6555ade3cd7081ea429dc5c3419e7535159212a96e0304a92e99b2ff282b7002aba1b63216d194d3d0647266aab15d055a3f835d09d2f4b6cbdef4cc035effec351f986a27b627c605247a05f31fb51bd7ba050625376440ac79c2f6f6515338c9dcd5d1ba969ba662d2a0aeda2b4666d4da7ba8fa1ef2687d713892d3be46c34ddd2fef330aa986b8af7a91674bdea70ddff1b0c58fb0739232f243d408027edbb577b273bdd0989c7c6b9d6fde56a81a23416b754a3c81b307683860f31faeb102c5e730929b75fe56ba44d72445ca4110f89
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69379);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/10/29");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug63304");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco NX-OS (cisco-sa-20130801-lsaospf)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco NX-OS device is affected by a vulnerability involving
the Open Shortest Path First (OSPF) routing protocol Link State
Advertisement (LSA) database. By injecting specially crafted OSPF
packets, an unauthenticated attacker could manipulate or disrupt the
flow of network traffic through the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a643e96");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2019 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

if (device != 'Nexus') audit(AUDIT_HOST_NOT, "affected");

if (model =~ "^1000[Vv]$") audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;

# Affected versions as of: 7/31/14
# All versions of NX-OS for Nexus 3000, 4000, 6000, and 9000 are affected
if (model =~ "^[346][0-9][0-9][0-9]([Vv])?$") flag++;

# Nexus 5000: 4,x, 5.x, 6.x, are affected, 7.0(0)N1(1) is the first 7.x release
if (model =~ "^5[0-9][0-9][0-9]([Vv])?$")
{
  if (ver =~ "^4\.") flag++;
  if (ver =~ "^5\.") flag++;
  if (ver =~ "^6\.") flag++;
}
# Nexus 7000: 4.x, 5.x, 6.0, 6.1 prior to 6.1(4a), 6.2 prior to 6.2(6) are affected
if (model =~ "^7[0-9][0-9][0-9]([Vv])?$")
{
  if (ver =~ "^4\.") flag++;
  if (ver =~ "^5\.") flag++;
  if (ver =~ "^6\.0") flag++;
  if (ver =~ "^6\.1\([1-3][a-z]?\)") flag ++;
  if (ver =~ "^6\.1\(4\)") flag ++;
  if (ver =~ "^6\.2\([0-5][a-z]?\)") flag ++;
}

# Check for OSPF configured
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ospf_interface", "show ip ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCug63304' +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
