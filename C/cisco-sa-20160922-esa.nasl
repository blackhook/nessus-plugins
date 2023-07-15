#TRUSTED 57c815ccc244bfa3f5641eb2a7197027603072f6c8bbdc971908193a6af423ef1492e732b0281af2012361fb99161342eb077e883c61790a8ea9026ebb474c9c58ed7bb251bd752205de7c59b0b84441e5f07180067a31e8b27b5d650d648a27575bd3f67301e0e713c0bff88e7b76a88223581e353f202652ebd89385150e9a50645748df68bc04cad44ebd16a8c69aa966f4d1a75a4b34b5b74a2088829627da2b132e74fd1fc9229d7fb8130ebc9ad4bc98320f6b0371cabf860d7b23cfe8feec62461a57e528e13c277c0c39277e8904eda0919b9d4128e686368a817abc405c8f23716f7bf776ced661e9917f2bbc074963b5cd918baf39ffeadd52a727b97523ca933f21d76c0b02768a19c52e2424373cbbe67a9b55ada22b260f052d13554b3e709aaa58adc7f1a7f854d75c3c0d24d97f00ccba09f8171b14ba9164e719d1274592ecf6eabf362d6f449f272168967399dce0135dfdfd267a42276663d15cd51a9f3407815bff82773df5979ac072b01b51c4128071128f8152f3f05bdb4d19aad258a24eb3e542c2485b321b93f5c234357685189462bf649418e7f82000cf1f8fb0fea99b02f33798655489b04f777b495931786bdbe559edd6ab4c2b7de4d8c20e4c75db6d537537a55d11ce700d3bfe43cd66d4c59c22a45bf1fd7492969abadc5825d13e67ee5362d13cb5159048a37551df3a28313d4c8ef8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93866);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-6406");
  script_bugtraq_id(75181);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb26017");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160922-esa");

  script_name(english:"Cisco Email Security Appliance Internal Testing Interface RCE");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco AsyncOS running on
the remote Cisco Email Security (ESA) appliance is affected by a
remote code execution vulnerability due to the presence of an internal
testing and debugging interface that was not intended to be shipped on
customer-available software releases. An unauthenticated, remote
attacker can exploit this by connecting to the interface, allowing the
attacker to obtain complete control with root-level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160922-esa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cc98b0e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb26017");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant updates referenced in Cisco Security Advisory
cisco-sa-20160922-esa. Alternatively, reboot the ESA device since
rebooting permanently disables the testing and debugging interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");

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

# ver is stored as x.y.z.abc rather than x.y.z-abc
if (ver == "9.1.2.023" || ver == "9.1.2.028" || ver == "9.1.2.036")
{
  display_fix = '9.1.2-041';
  vuln = TRUE;
}
else if (ver == "9.7.2.046" || ver == "9.7.2.047" || ver == "9.7.2.054")
{
  display_fix = '9.7.2-065';
  vuln = TRUE;
}
else if (ver == "10.0.0.124" || ver == "10.0.0.125")
{
  display_fix = '10.0.0-203';
  vuln = TRUE;
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

override = FALSE;
# If local checks are enabled, confirm the version of the
# Enrollment Client Component.  Only versions earlier than
# 1.0.2-065 are affected.
# If local checks are not enabled, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/ecstatus", "ecstatus");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Enrollment Client\s+\d+", string:buf))
  {
    version = eregmatch(pattern:"Enrollment Client\s+([0-9\.-]+)", string:buf);
    if (!empty_or_null(version))
    {
      ecstatus = version[1];
      ver = str_replace(string:ecstatus, find:'-', replace:'.');
      if (ver_compare(ver:ver, fix:'1.0.2.065', strict:FALSE) == -1)
        vuln = TRUE;
      else
        audit(AUDIT_HOST_NOT, "affected because the version of the Enrollment Client Component installed is not affected");
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
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
    security_hole(port:0, extra:report+cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
