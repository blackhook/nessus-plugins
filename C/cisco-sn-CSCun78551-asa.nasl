#TRUSTED 759035e51beb11bae986fd328a5c736e5c3f3e8ca9aec5882d97ed71b57311de052ae12e9bc62c555ea98f6ef4f494d3b237cd4805d8c3230672e7be1c5b1f34c8aa69ca9fd775e96a55654d2f4601ad0adf16a0a90079285f4bf6e76ffe4accf40f25e9f5ae03081e13e64fa2ef5b677b224adf609bbd2c92d30c340cea7494ee50ac570a811dcf9733c91146ac8115619cefe71c5c8281c453a9a881069e426e18a79ae23ec7d4bf4b8c347d7753e59cb911de0da12b5ec66b0ceff3ee2301f4fb172830313a67cfa43ee6c2bdd3cc79bdfc53cfd3ceb764183c2c6916b01d07235a861799993ce549821aceeb7b4f85b2dcdcea1c24197780c1e8a724eb0b8475d3bb55c9ff214a5139a695a889b695a693eb9498da6264a6c3e32aad9d3f95632a5f280e2f96a40bb8bda1824b625546b45790a3bd32c473732dd239a17dff0fb91a12a2a06d70fa0092816502b55b16e94407fb02f08959f45cd8c3e3f6ea5fd1a6c249f64054c51cd1711d86a4588705bdc8434c4e9a545200cbac6f2187207424b200e1ecef95a24831c2919923cc580964672fd7ec1af888f96188f89d49e6f35d99bbae11997e6b3ab79ff2212d55c2b977bc11f2b43e40664ffa55dd3011bc74b148eaf61b2c0b069369703c3a9b9fb93cd5efd8b8b907d5f37c4922d9853b40aca1dd46bbc7a1ead1b3549a867ff7122cb7042db513f3a2039b7d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79744);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2181");
  script_bugtraq_id(67221);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun78551");

  script_name(english:"Cisco ASA HTTP Server Information Disclosure (CSCun78551)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by an information disclosure vulnerability in the HTTP
server. An authenticated, remote attacker can exploit this, via a
specially crafted URL, to access arbitrary files on the device.

Note that this issue affects devices in the single or multiple context
modes. However, when in multiple context mode, only a user in the
admin context can exploit this issue.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34137
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e293284f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34137");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCun78551.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver   = NULL;

# Convert 'Cisco versions' to dot notation
# a.b(c.d) to a.b.c.d
# a.b(c)d  to a.b.c.d
ver_dot = str_replace(string:ver, find:'(', replace:'.');
matches = eregmatch(string:ver_dot, pattern:"^(.*)\)$");

if (matches) ver_dot = matches[1];
else ver_dot = str_replace(string:ver_dot, find:')', replace:'.');

if (
  ver =~ "^8\.0([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.0.5.31", strict:FALSE) <= 0 ||
  ver =~ "^8\.2([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.2.5.48", strict:FALSE) <= 0 ||
  ver =~ "^8\.3([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.3.2.40", strict:FALSE) <= 0 ||
  ver =~ "^8\.5([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.5.1.19", strict:FALSE) <= 0 ||
  ver =~ "^8\.6([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.6.1.13", strict:FALSE) <= 0 ||
  ver =~ "^8\.7([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.7.1.11", strict:FALSE) <= 0
)
  fixed_ver = "Refer to the vendor.";

else if (ver =~ "^8\.4([^0-9]|$)" && check_asa_release(version:ver, patched:"8.4(7.23)"))
  fixed_ver = "8.4(7.23)";

else if (ver =~ "^9\.0([^0-9]|$)" && check_asa_release(version:ver, patched:"9.0(4.12)"))
  fixed_ver = "9.0(4.12)";

else if (ver =~ "^9\.1([^0-9]|$)" && check_asa_release(version:ver, patched:"9.1(5.7)"))
  fixed_ver = "9.1(5.7)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA", ver);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # Check if HTTP is enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config",
    "show running-config"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"http server enable", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override)
  audit(AUDIT_HOST_NOT, "affected because the HTTP server is not enabled.");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver         +
    '\n  Fixed version     : ' + fixed_ver   +
    '\n';
  security_warning(port:0, extra:report + cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
