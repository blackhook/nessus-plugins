#TRUSTED 4c1c7b3cde35b42651c9788cd4ea587aebf9b38b945338f12acc80f6e1d3cbf20eec6c06404ccd710be2bc994a74383e8db76f35ea7a35046329dc2e2878f52484045d11cbd6e4efc11b2bca3f69fa5fc92db98390864124d11adfe2970f8c3222dff54dc09a1e488e45d63a7e9c0adcafa9c8ad7f1c3c4fd7cc5a59168d2377b6dc38667b70b206ec9bf266cb0387a0220ccf8a41e1860399576803dbec840b083af2c9915ad0930e4f1183c55bf93668fa78a807795c9930807ac32c4c8d97f5a452da67cecacdbf89b5175545ea88451bf862762670340581f16d9b4a597f032a03f09c6b23191151c21acf64baa803d9d14812c76b2824b4fbcab782e1444991ac8fd111938efdf6fc26e764639177641fa3ca97358694823fc65659afa10180c26f9d62c4a395dc1d84fc64caf39b7b7973060e4c1bbaf74aa298f7643ac71b643a67ef76e9e314cef29183f0bc8ac257818b91cc0954f93ef1e3a0cb693466ad3879b0a9c8b3a0fe7a50781a307b38758da14299274cd0232b7cb07e873ecd173ca1900157c5df4b6f2cb33b515994236c0d5915abdb9113a17639b2a3cd85e7a3f61e20c5fe27f88602eecee2979e677116c74302271a888ef9b3bf9d31bec154f8b1d3780641cbce641dcab8d65cad50fa030af94a593f9b1d169891d5c8c44e3a68cbefc461ecf571a543a36243971a02479cd7d60b2e0827dc6ab1
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72668);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-0710");
  script_bugtraq_id(65662);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj16824");
  script_xref(name:"IAVA", value:"2014-A-0031");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140219-fwsm");

  script_name(english:"Cisco Firewall Services Module Software Denial of Service (cisco-sa-20140219-fwsm)");
  script_summary(english:"Checks the FWSM version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Firewall Services Module (FWSM) device is affected by
a denial of service (DoS) vulnerability due to a flaw in the cut-through
proxy function.  A remote, unauthenticated attacker could potentially
exploit this vulnerability to cause a reload of the affected system,
with repeated exploitation leading to a DoS condition."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140219-fwsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee45dacd");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140219-fwsm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_fwsm_version.nasl");
  script_require_keys("Host/Cisco/FWSM/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/FWSM/Version");

flag = 0;
fixed_version = "";
local_checks = 0;

# prepare for local checks if possible
if (get_kb_item("Host/local_checks_enabled"))
{
  local_checks = 1;
}

if ( (version =~ "^3\.1(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.1(21)") > 0) )
{
  flag++;
  fixed_version = "3.2.x or later";
}

if ( (version =~ "^3\.2(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(28)") < 0) && (cisco_gen_ver_compare(a:version, b:"3.2(21)") > 0))
{
  flag++;
  fixed_version = "3.2(28)";
}

if (version =~ "^4\.0($|\.|\()" && (cisco_gen_ver_compare(a:version, b:"4.0(16)") > 0))
{
  flag++;
  fixed_version = "4.1 or later";
}

if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(15)") < 0) && (cisco_gen_ver_compare(a:version, b:"4.1(6)") > 0))
{
  flag++;
  fixed_version = "4.1(15)";
}

if ( local_checks )
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_aaa_authentication",
      "show running-config aaa authentication| include match|include"
    );
    if (check_cisco_result(buf)) flag = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
