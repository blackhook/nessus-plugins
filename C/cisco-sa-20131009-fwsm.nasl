#TRUSTED 18cdf8f2477710e8765581787e6257647f4e482267028177cf2e12553f9415e4e8fb75394ff243333c1bb1e7bbd1868a0b10ebae89437d602506c7e619bd33382e6911f7cfb624eb21f2bc3b5dada872e872a9c4f7b6b12d4fcc11b47fca91a3b8d0e2097651805a031af4edb58f5949effc097e7a962303c5f80841c4a09e4f503de91174eeec2ed2b8d9721874ddfe526abde37f5bb95e0852272765e1f173b1c3d1d40fe4fed89db2cfeeb98a669776daf6f59dbe020bc03c56f01036af0ae3657523cc0a689908584cade9ce9a83a3d4890586916a73b5c8c3bdd92ca736fd0c4a11d7a3db3b709630cad97dd0d8bc4a04dff58279ca27c9f7744210bfb286c399b732a40d7c8f7d83be67d31dfed2cd4b0ded9311b651eccdd64234ad55b75ac6093d6423f32f283d9b4cf09e944ceb96434e352be25ce1383e80a8f796280d1b8a451f2e5ad744b06d9da209fa0c7b73bb543790e219ce8f3770157faf362d828b3997338b459a8aa8c03a1ff1405e316191589280cf6648f066087a89dea3bca134aca53e7605cb6209f71f375d36aba3a71fd8a4fa4fd5fb265729b027342bad8c4e4f8c7e217c1a8ede7185ae68d9a83d201a6cd18e564710f4e46e5f6fb39fec7d403c7ccbbc7735a604cddd32b862ce0b296c7b1df22713920333c5d944855569d087529a82f29dcc714dcfec9b9cf7945ee9ee37b2fa7b4df3b0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70493);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id("CVE-2013-5506", "CVE-2013-5508");
  script_bugtraq_id(62912, 62918);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue46080");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui34914");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131009-fwsm");

  script_name(english:"Cisco Firewall Services Module Software Multiple Vulnerabilities (cisco-sa-20131009-fwsm)");
  script_summary(english:"Checks the FWSM version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Firewall Services Module (FWSM) device is affected
by one or both of the following vulnerabilities.

  - A flaw exists in FWSM that could allow an authenticated,
    unprivileged, local attacker to execute certain commands
    in any other context of the affected system.
    (CVE-2013-5506)

  - A flaw exists in FWSM in the SQL*Net Inspection Engine
    that could allow a remote denial of service that could
    be triggered when handling a malformed TNS packet.
    (CVE-2013-5508)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131009-fwsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e584d57");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131009-fwsm.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5506");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_fwsm_version.nasl");
  script_require_keys("Host/Cisco/FWSM/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/FWSM/Version");

flag = 0;
override = 0;
fixed_version = "";
local_checks = 0;

# prepare for local checks if possible
if (get_kb_item("Host/local_checks_enabled"))
{
  local_checks = 1;
}

# CSCue46080
temp_flag = 0;
if ( (version =~ "^3\.1(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.1(8)") > 0) )
{
  temp_flag++;
  fixed_version = "3.2.x or later";
}

if ( (version =~ "^3\.2(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(25)") < 0) && (cisco_gen_ver_compare(a:version, b:"3.2(4)") > 0))
{
  temp_flag++;
  fixed_version = "3.2(25)";
}

if (version =~ "^4\.0($|\.|\()")
{
  temp_flag++;
  fixed_version = "4.1.(14) or later";
}

if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(13)") < 0) )
{
  temp_flag++;
  fixed_version = "4.1(13)";
}

if ( local_checks )
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_mode", "show mode");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"multiple", string:buf)) { temp_flag = 1; }
    }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco Bug Id        : CSCue46080' +
    '\n    Installed version : ' + version +
    '\n    Fixed version     : ' + fixed_version + '\n';

  flag = 1;
}

# CSCui34914
temp_flag = 0;
if (version =~ "^3\.1($|\.|\()")
{
  temp_flag++;
  fixed_version = "3.2.x or later";
}

if ( (version =~ "^3\.2($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(27)") < 0) )
{
  temp_flag++;
  fixed_version = "3.2(27)";
}

if (version =~ "^4\.0($|\.|\()")
{
  temp_flag++;
  fixed_version = "4.1.(14) or later";
}

if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(14)") < 0) )
{
  temp_flag++;
  fixed_version = "4.1(14)";
}

if ( local_checks )
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_service-policy", "show service-policy");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"[Ii]nspect\s*:\s*sqlnet", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco Bug Id        : CSCui34914' +
    '\n    Installed version : ' + version +
    '\n    Fixed version     : ' + fixed_version + '\n';

  flag = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    security_warning(port:0, extra:cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
