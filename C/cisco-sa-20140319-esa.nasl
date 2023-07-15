#TRUSTED 9b4d5049fafbdb07a84acf95ad02dd0593b04c9d5b6a0b850684da26a520901ac9c0647dae0ea3e7627a7469116dabe40eec5a9c9c8c5f95aff9c0c9776bac9c93ff22d398601eae51cfae866dc840348f24de76efb3bb03a00d8bdfb1f7de0109677176509dc578c64f9c4c811d1498625b60243bc1d2485a3ce591c9add119c27c867538cb3e41f8b78f6610b1a8ac6c70055dd95d07ae20d20d8bf23050846e8baa43c4818bd6333927c4af657a579121fce4aba50f2a572483df6ae1914db074673b143aba4e9374db359e7bdbc1e05ab639683b991391c1e3e8282f9cfd4f0ec1a1065622372faa7ea9c5e7f174d3a1dba0ccd470c8d01cdeb77392fc46bad82d2d0d7347579b01063c3d22432681cc84e454af73ee6c24d3a920dd9523ff5396ea6ebf9ba31c0e1d4e5e6e79ea4fc7727bb17ff81e10a9533cd5c19073a1f5f7acc776f32829ab7d46805a96f00a821f590d058d84a1da98aca798c896a2ab3418dee47f58b7ebe367b7ab83d3eaae57411142673ac80b7c307a801e29f0368a534b48842afbd312d16412c4ba2898aa65de33e8bcd6b9b7f0471591c9fa3b958dab1886e1d2e6baf41863dffe05da86e8c857b54cb97e6b10124dbf7e39a4a5d37ee2a092ad6e5666cbfe6fb790cb840711d4e9af5a3d7ab614cb9cb6effefca0302a4577bbb64ef0251b5b6ee17605f591babcd169a0b204beee528f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73210);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-2119");
  script_bugtraq_id(66309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug79377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140319-asyncos");

  script_name(english:"Cisco AsyncOS for Email Security Appliances Software Remote Code Execution (CSCug79377)");
  script_summary(english:"Checks ESA version");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
AsyncOS running on the remote Cisco Email Security (ESA) appliance is
affected by a remote code execution vulnerability in the
Safelist/Blocklist (SLBL) function due to improper handling of SLBL
database files. An authenticated, remote attacker can exploit this
vulnerability to execute arbitrary code with the privileges of the
'root' user.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140319-asyncos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66d063e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140319-asyncos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Services/ftp", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

vuln = FALSE;

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

if (ver =~ "^[0-6]\." || ver =~ "^7\.[01]\.") # 7.1 and prior
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.3\.")
  display_fix = '8.0.1-023';
else if (ver =~ "^7\.5\.")
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.6\.")
  display_fix = '7.6.3-023';
else if (ver =~ "^7\.8\.")
  display_fix = '8.0.1-023';
else if (ver =~ "^8\.0\.")
  display_fix = '8.0.1-023';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

# Compare version to determine if affected. FTP must also be enabled
# or paranoia setting must be above 1.
if (
  ver_compare(ver:ver, fix:fix, strict:FALSE) == -1 &&
  (get_kb_list("Services/ftp") || report_paranoia > 1)
) vuln = TRUE;

# If local checks are enabled, confirm whether SLBL service is
# enabled. If they are not, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/slblconfig", "slblconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Blocklist: Enabled", string:buf))
    vuln = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    if (!local_checks) report +=
      '\n' + 'Nessus was unable to determine whether the End-User Safelist /' +
      '\n' + 'Blocklist service is running because local checks are not' +
      '\n' + 'enabled.' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);


