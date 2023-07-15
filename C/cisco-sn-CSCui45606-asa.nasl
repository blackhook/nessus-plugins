#TRUSTED 0c39ab74749fe0aaa930ea74fb6c3d8287e7cd222f12b0ec5c39b496760148987baba23e61ae33a129b5ba5e3af7256e77eb98a5865787dee84e99f8cd26f74f5a63035f0129402f01ac674fabf2ed94a919503ef309a6111712d8f119faaba0d61b28783dc96405216b4ec5fc9770124d854762a4737f43df6bf579b9e253cf69a1b361fe1ad971a4f19e6262c35865f5b68c9d54956c05b0524385664e8eca7565dac4422a45626db01617e9deab0f39f22f5b5ac2c42a4c77ff19ca180ea2129d5980d8dc8a62e0372f7f8bc9d3798910ba573ab16ef0aab8860acb77b729b57a6ce3833b9a947bda3e78e52ae965f0fde2e111ef187e95d44123f491e046bc879c5dc0ef10c0804aa472f8e93a690961e8c39eab9f3f46bb6fe64cd72e9846693624e720a0a9e033982aceea0e1dbe5a239776f76a04d2d735edc2693a68567a7d52f6caa2a2d6f262fe88066e68bfc4b4df7562b1f7036a3d606aa709965207d827d014106aad08ae50f12b6a7b6f28c7b07ee69376ef0dfe581b5ad2d348801b5db9a6a057bb42ae7d362ddc99ef974f4a6509ec80e104404f7e43f31c0250a126f8112af9d28f52985cf89641669400dcc470669aa1bec261fa2e547bcd3688540b5dbab4a1b6ac008f2e898483f8b67e24bb84378ac83c3c575cf391cb9af43209572f3e30da9f1e88e4e41016552ee30d742802643d376b910994bc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76588);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5567");
  script_bugtraq_id(68504);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui45606");

  script_name(english:"Cisco ASA Inspection and Filter Overlap DoS (CSCui45606)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability due to improper handling
of traffic matching both filtering and inspection criteria that could
allow a remote attacker to cause the device to reset.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34911
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03e557ac");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui45606");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Bug ID CSCui45606 or
apply the vendor-supplied workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASA 5500-X series');

fixed_ver = NULL;

if (ver == "8.4(6)")
  fixed_ver = "8.4(7.1)";
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if the misconfiguration is present;
# can be removed via workaround
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_service", # currently, should not be present
    "show run | include service"
  );
  if (check_cisco_result(buf))
  {
    if (
      "service resetoutside" >< buf &&
      "service resetinbound" >< buf &&
      "no service resetoutbound" >!< buf
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
