#TRUSTED 1fac5846010279512714e3fad8169c2adcf601e7c67a0a63445b2f2e601adefc7cbf4fa7c0c8c1caee7096f21146836e0ea557cf8932d369a24fc8278dbbe6fa6a213a2c9983097710d4a454d772d6a5033c19923317c18fde844cc1b8b4cf26da057a3026cf75f162ca6af704813169650efdfbef806cc08975136ea937fde08328a423dd4d8cca2e20109435d6a131d9e09fc62b30558a4f77d95cc007e734b07e591e6dd525e451bb14a9846eafd2bb5eb7d063a6cf59cd8a257461557268e1c2fbe8295bd3c9cf7a97b05d9ddb80476821f7ee7cffa7d6ae1fe1ede6c1230e822c155f30af92fd6da9af51dc4461c5a0b125f34e180578855452b63f518696af738c45c2e9ecf3211a919c2f018fdba4c72d1894f628c5330322f56d217ddec1f46834a8196f048dc4bca3b9b1e878b096b4d72434e6e45be57f3b457fa60effb31966bc63035ecb20a6852bcb34ef29ddab74ced2292ff5b8e437109ed7946fe1a9359af2ac37e6d55d676fca93f6dbf91f47da7961526b2f35895738e4f65b1a665f86953a95cd3e982dd9400d90e57843d8937a7d4402844595897c3991eb9f79700ddb78fcafab8c434852b512ddab0c2374c17fb2f5b7378cae1ea501a06d9cf95be9634435dd541e399a2d02249342650f79ba848e07a0b62446bfa3d852218ab37c2358814195bbec2cfde2b68a77265b0ac2a6e5aca7b6223825
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131023-iosxr.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71438);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2013-5549");
  script_bugtraq_id(63298);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh30380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131023-iosxr");

  script_name(english:"Cisco IOS XR Software Route Processor Denial of Service Vulnerability (cisco-sa-20131023-iosxr)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software Releases 3.3.0 to 4.2.0 contain a vulnerability
when handling fragmented packets that could result in a denial of
service (DoS) condition of the Cisco CRS Route Processor cards listed in
the 'Affected Products' section of this advisory.  The vulnerability is
due to improper handling of fragmented packets.  The vulnerability could
cause the route processor, which processes the packets, to be unable to
transmit packets to the fabric.  Customers that are running version
4.2.1 or later of Cisco IOS XR Software, or that have previously
installed the Software Maintenance Upgrades (SMU) for Cisco bug ID
CSCtz62593 are not affected by this vulnerability.  Cisco has released
free software updates that address this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131023-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15a5e418");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131023-iosxr."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

cbi = "CSCuh30380";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '3.8.1' ) flag++;
if ( version == '3.8.2' ) flag++;
if ( version == '3.8.3' ) flag++;
if ( version == '3.8.4' ) flag++;
if ( version == '3.9.0' ) flag++;
if ( version == '3.9.1' ) flag++;
if ( version == '3.9.2' ) flag++;
if ( version == '3.9.3' ) flag++;
if ( version == '4.0.1' ) flag++;
if ( version == '4.0.3' ) flag++;
if ( version == '4.0.4' ) flag++;
if ( version == '4.1.0' ) flag++;
if ( version == '4.1.1' ) flag++;
if ( version == '4.1.2' ) flag++;
if ( version == '4.2.0' ) flag++;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"CRS-16-RP", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (!flag)
{
  if ( version == '4.0.3' ) flag++;
  if ( version == '4.0.4' ) flag++;
  if ( version == '4.1.0' ) flag++;
  if ( version == '4.1.1' ) flag++;
  if ( version == '4.1.2' ) flag++;
  if ( version == '4.2.0' ) flag++;

  if (get_kb_item("Host/local_checks_enabled"))
  {

    if (flag)
    {
      flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"CRS-16-PRP", string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
