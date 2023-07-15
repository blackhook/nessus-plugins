#TRUSTED 50ce4eb53ff5f515ec275c08486326604ef7358f4f4a34abeaaf978df8e1fd980cb11f777e031d0e656f2d476490e1e21d822ab12a798462571a1918efeb4872c7ccc4d55173ced5fcd0c6d19f5cdeac551a5af1d5a70f3ce4781cb7985a8df78ac7ff6916fd258deca5a75f8a0795b8bf507a92cc326d65680f744fef2a5da574b7d3c8081d0213d795a2bc84d63b2c7b24bc006a9ea886ead8687e35105b3439577b658aea11378f6b797835f0b72667d36eafbe9147e2b060963e841713775e940d09ebb459738834017289d915b16e850983fd36f3bef6a98ebc8f6bc556a24c197d0a58bc2ed57ded0886221f18075fec2aeefe5425e754da12272c50d9df9c92185b3349c95fc6dbf15972ed67004c08eeac738fe72b14bd280692a86c7000f38e7fb5afbbc3c8b5c8770530ce26049cb4a111ea3661fc262e057255737170863491a272fde85ca2686de2883f9cf93be8c2d0061ac4beb69342af874badb5883089628b394da2d00ed413dc479aa71bfe8ea66e543d85b6f96c276349710799e235f1c1f5ee633257933d2b564e35cda22ef99a93510a47217996dacd7ae61512ec574c03232ef400e2aacfb04e122844df4701190ff680eb663d98498eb804d58cd12ebb6bed63e84cc47ddcf28b24def28a5ed1fe69552ede9ae2b2822fc6a66c79210eff5efc66992570c6a28b328495f796f8ed334c01e5be7c24
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93480);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-7547");
  script_bugtraq_id(83265);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160218-glibc");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy36553");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy38921");
  script_xref(name:"EDB-ID", value:"39454");
  script_xref(name:"EDB-ID", value:"40339");
  script_xref(name:"CERT", value:"457759");

  script_name(english:"Cisco Nexus 3000 / 9000 Series GNU C Library (glibc) getaddrinfo() RCE (cisco-sa-20160218-glibc)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS software running on the remote device is
affected by a remote code execution vulnerability in the bundled
version of the GNU C Library (glibc) due to a stack-based buffer
overflow condition in the DNS resolver. An unauthenticated, remote
attacker can exploit this, via a crafted DNS response that triggers a
call to the getaddrinfo() function, to cause a denial of service
condition or the execution of arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160218-glibc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae76a668");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy36553");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy38921");
  # https://security.googleblog.com/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94dd3376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or install the relevant 
SMU patches referenced in Cisco bug ID CSCuy36553 / CSCuy38921.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 9000 series systems
# and the 3000 series systems listed in the advisory/bugs
if (
  device != 'Nexus' || 
  model !~ '^(3016|3048|3064|3132|3164|3172|3232|3264|31128|[9][0-9][0-9][0-9][0-9]?)([^0-9]|$)'
  ) audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

override = 0;
check_patch = 0;
vuln = 0;

if ((
  # Only CSCuy36553
  version =~ "^6\.1" ||
  version =~ "^7\.0\(3\)I1"
  ) && model =~ '^(3164|3232|3264|31128|9[0-9][0-9][0-9][0-9]?)([^0-9]|$)'
) vuln ++;
# CSCuy36553 & CSCuy38921
else if (
  version =~ "^7\.0\(3\)I2\(1[a-z]?\)" ||
  version == "7.0(3)I2(2)" ||
  version == "7.0(3)I3(1)"
) vuln ++;
else if ( version == "7.0(3)I2(2a)" || version == "7.0(3)I2(2b)" ) 
{
  # flag vuln in case we can't check for the patch.
  vuln ++;
  check_patch ++;
}
else audit(AUDIT_HOST_NOT, "affected");

# check for the patch on 7.0(3)I2(2[ab])
# audit if patched, assume vuln otherwise
if (check_patch && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");
  if (check_cisco_result(buf))
  {
    # Modular products 2a - 2 patches
    # nxos.CSCuy36553_modular_sup-1.0.0-7.0.3.I2.2a.lib32_n9000
    # nxos.CSCuy36553_modular_lc-1.0.0-7.0.3.I2.2a.lib32_n9000
    if ( version == "7.0(3)I2(2a)" && model =~ "^(9504|9508|9516)")
    {
      if 
      ( 
        "CSCuy36553_modular_sup" >< buf && 
        "CSCuy36553_modular_lc" >< buf
      ) 
      audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patches are installed");
    }
    # ToR products 2a - 1 patch
    # nxos.CSCuy36553_TOR-1.0.0-7.0.3.I2.2a.lib32_n9000
    else if (version == "7.0(3)I2(2a)")
    {
      if ("CSCuy36553_TOR" >< buf) audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patch is installed");
    }
    # All products 2b - 2 patches
    # nxos.CSCpatch01-1.0.0-7.0.3.I2.2b.lib32_n9000
    # nxos.CSCuy36553-1.0.0-7.0.3.I2.2b.lib32_n9000
    else if ( version == "7.0(3)I2(2b)")
    {
      if 
      ( 
        "CSCpatch01" >< buf && 
        "CSCuy36553" >< buf
      ) 
      audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patches are installed");
    }
    
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fix               : see solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
