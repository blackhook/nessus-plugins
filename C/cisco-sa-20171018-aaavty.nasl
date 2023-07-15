#TRUSTED 3a2aad652e518a2aea7bda82a5fa51864216acf09f51d1d14debc6e6833a6237759b979758201c5d8457c5944790a15092cf6737d832b098705f9f19e82df523009abaf2234294f81b5b38fddb5895aade6986ee3eb29dfdeed4bd87058c24fef9125c49ebb95f50f8d715c608de802b0b987fd725367ced3b520d7b4e307304cfe844fc9046a38ee431f3e08f562a839d9949a03847029ee8dc92b1eb7bcaebf8adeeaa831d8766279d8cef533b218ceac4e5b01005a986ed75769c551422c0e84b13f9c2e445d2f22419aa79347530ce1f26d0d9f54984bd602a3817fb88cbf5598ecc99daea910c06702ebfab81b92a1d9d44f6a79a3bc002b7ddb052f310e0acd2d7a57b3487701119639205717cf9cf3857ad648da4cb8ed1417ad8c543a54899a82c6362085a3d60a9b374647dca16c073d39147b229cdb71a2c75376e497e79dff64c7defbcffa4bd660555f0f5dbb35c8258d63466679ec92b5c33912b072510af4cac747ab9e89a80dce435ffb70dc380a16edec10bffd60d895264a5c689f59b67398fb40454e5c365257bc2e7d5fc7715b63954cb2f9f3739dc4f674ea16ce15118ea3021c48a3ef1b583467fa6c4ad4265e787d166586c3137562c35fa48cc5f4b174f70b551f1c68fc65dfdb6b5817309b3b49e87002f5a3e4f9129e880a0145de42c011c88223bf00cd4ca3be920ae633e8c1d916ea0b7ce17
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104177);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-3883");
  script_bugtraq_id(101493);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq58760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq71257");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur97432");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus05214");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux54898");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb93995");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc33141");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd36971");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve03660");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf64888");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg41173");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171018-aaavty");

  script_name(english:"Cisco NX-OS System Software Authentication, Authorization, and Accounting Denial of Service Vulnerability Vulnerability");
  script_summary(english:"Checks the Cisco NX-OS Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco NX-OS Software is
affected by a vulnerability in the authentication, authorization,
and accounting (AAA) implementation of NX-OS System Software that
could allow an unauthenticated, remote attacker to cause an affected
device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171018-aaavty
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b71cc502");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20171018-aaavty or use the referenced vendor
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3883");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# not affected if not MDS or Nexus
if ('MDS' >!< device && 'Nexus' >!< device && 'UCS' >!< device)
  audit(AUDIT_HOST_NOT, "an affected device and/or model");

# Nexus models affected 1000V, 1100, 2000, 3000, 3500, 5000, 6000, 7000, 7700, 9000, 9500 R (handled below)

# Also affected:
# Nexus 9500 R-Series Line Cards and Fabric Modules
# Unified Computing System (UCS) 6100 Series Fabric Interconnects
# UCS 6200 Series Fabric Interconnects
# UCS 6300 Series Fabric Interconnects

# We do not have UCS Fabric devices, nor do we
# know the banner. For now we are only checking them if
# we are in paranoid mode.

# the paranoid series checks are 1000, 2000, 2000, 5000, 6000, 7000, 9000/9500
# non-paranoid series checks are 1000, 2000, 3000, 5000, 6000, 7000

if (report_paranoia >= 2)
{
  if (('Nexus' >< device &&
    model !~ "^[1235679][0-9][0-9][0-9]([^0-9]|$)$" &&
    model !~ "^95[0-9][0-9]([^0-9]( R)?)[^0-9]|$") &&
    ('UCS' >< device && model !~ "^(61|62|63)[0-9][0-9]([^0-9]|$)$") &&
    ('MDS' >!< device))
  {
    audit(AUDIT_HOST_NOT, "an affected device and/or model");
  }
}
else
{
  if (('Nexus' >< device &&
    model !~ "^[123567][0-9][0-9][0-9]([^0-9]|$)$") &&
    ('MDS' >!< device))
  {
    audit(AUDIT_HOST_NOT, "an affected device and/or model");
  }
}

flag = FALSE;
fix = NULL;
override = FALSE;


# Cisco Nexus 1000V Switch
if ('Nexus' >< device)
{
  if (model =~ '^1000V' || model =~ "^11[0-9][0-9]")
  {
    if(version =~ "^([0-3]\.[0-9]|4\.[0-2]|5\.2)")
      fix = "See advisory";
  }

  # Cisco Nexus 3000
  else if (model =~ "^3[0-9][0-9][0-9]([^0-9]|$)" && model !~ "^35[0-9][0-9]([^0-9]|$)")
  {
    if(version =~ "^([0-5]\.[0-9]|6\.0)")
      fix = "6.0(3)I6(1)";
    else if(version =~ "^7\.0")
      fix = "6.0(3)I6(1)";
  }

  # Cisco Nexus 3500
  else if (model =~ "^35[0-9][0-9]([^0-9]|$)")
  {
    if(version =~ "^([0-5]\.[0-9]|6\.0)")
      fix = "6.0(2)A8(8)";
  }

  # Cisco Nexus 2000, 5500, 5600, 6000
  else if (model =~ "^5[56][0-9][0-9]([^0-9]|$)" || model =~ "^2[0-9][0-9][0-9]([^0-9]|$)"
      || model =~ "^6[0-9][0-9][0-9]([^0-9]|$)")
  {
    if(version =~ "^([0-4]\.[0-9]|5\.[0-2]|[67]\.0|7\.[1-3])")
      fix = "7.3(3)N1(1)";
  }

  # Cisco Nexus 5000
  else if (model =~ "^5[0-9][0-9][0-9]([^0-9]|$)")
  {
    if(version =~ "^([0-4]\.[0-9]|5\.[0-2])")
      fix = "See advisory";
  }


  # Cisco Nexus 7000, 7700
  else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
  {
    if(version =~ "^([0-4]\.[0-9]|5\.[0-2]|6\.[0-2])")
      fix = "6.2(20)";
    else if(version =~ "^7\.2")
      fix = "7.2(3)D1(1)";
    else if(version =~ "^7\.3")
      fix = "7.3(2)D1(2)";
    else if(version =~ "^8\.0")
      fix = "8.0(2)";
    else if(version =~ "^8\.1")
      fix = "8.1(2)";
    else if(version =~ "^8\.2")
      fix = "8.2(2)";
  }
  else if (report_paranoia >= 2)
    # Paranoid checks
    # Cisco Nexus 9500 R Series
    if (model =~ "^95[0-9][0-9]\s?R$")
    {
      if(version =~ "^7\.0")
        fix = "7.0(3)F3(1)";
    }

    # Cisco Nexus 9000
    else if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)" && model !~ "^95[0-9][0-9]\s?R$")
    {
      if(version =~ "^6\.1|7\.0")
        fix = "7.0(3)I6(1)";
    }

}
# Cisco MDS
else if ('MDS' >< device)
{
  # 5.2 and 6.2
  if(version =~ "^[56]\.2")
    fix = "6.2(23)";
  # 6.3 and 7.3
  else if(version =~ "^[67]\.3")
    fix = "7.3(1)DY(1)";
  }

# Paranoid checks for UCS
else if (report_paranoia >= 2)
{
  if('UCS' >< device)
  {
    if(version =~ "^([0-2]\.[0-9]|2\.[0-2])")
      fix = "2.2(6c)";
    else if(version =~ "^3\.0|3\.1")
      fix = "3.1(2b)";
  }
}



if (!isnull(fix) && (fix == "See advisory" || cisco_gen_ver_compare(a:version, b:fix) < 0))
{
  flag = TRUE;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if(flag)
  {
    flag = FALSE;
    buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include aaa", "show running-config | include aaa");
    if (check_cisco_result(buf))
    {
      if ("aaa" >< buf)
      {
        flag = TRUE;
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;

    if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because AAA is not configured");
  }
}


if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    fix      : fix,
    bug_id   : "CSCve03660/CSCvc33141/CSCus05214/CSCus05214/CSCuq71257CSCuq58760/CSCur97432"
  );
}
else audit(AUDIT_HOST_NOT, "affected");
