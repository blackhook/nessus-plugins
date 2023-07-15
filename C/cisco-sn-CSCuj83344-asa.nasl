#TRUSTED 17aa9e0d42e1cfde1ea2648324b7ef7885c7b20d6f7bfd13aabf395cb519bcc952b8f6dc2bd8669c51daf104e800d302e9cafaa94f5d0ac74a0b7911b4d1d70be9065e4b4a54041425fd49536575ac31e6734779e7d14f560b2793eae3e44924be2b6925b93d4430d0a128e2dd170360d8509ff2cecb31afd75a5d763a15487dd003bdf30ed6c18b0d738533a35af279b646e411bbb27018b050891f250c0dbabe9b402fad192a5d7554a1ffffb6a09a642899beca24ae954639c69d69aabfb28fe6b93a88c6424c1d8965ee358b0de17dcd7538a8c4cbf263330aaf15102479ad9680fcc84dd70bacab2f79ced803d198915a8a096504653eedb9acca21ad8ec0ecbf606924a3bca0661d83b8d6183462cc0599cee5f8af60e465b2ceb9517c181af296f916ddff6698874a78c620dd4cb82345733333e6ccb2d81d72d264bb37e679735ad6240695364efef7d400699e8aadfe0e34e217063a05678bcbea58b0b7086d2c29e64dd73a28509623e0573930748e8a9beef6cb4d5db453cd4a4d1b9620141c000b77099691dd6de955a4247858c8d3fdb32b2887a2b6d49771d339ecf36747fc5458e63a7e4b12cd04dbe4e1ccf9df8caa499195b3807ce1ebfa1e75b3a267db3c7db1c3b3d35a7180aaab8e2eaca93882567d499d0d7e7dc5674b9cf2e8611d9fa4093dbd805d48d4cf3db96c0d0a309dc1e56500222ebed66f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77411);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-6691");
  script_bugtraq_id(68517);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj83344");

  script_name(english:"Cisco ASA WebVPN CIFS Share Enumeration DoS (CSCuj83344)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability in the WebVPN CIFS
(Common Internet File System) access function due to missing bounds
checks on received responses when enumerating large amounts of shares
on a CIFS server. A remote, authenticated attacker can exploit this
issue by attempting to list the shares of a CIFS server with a large
amount of shares.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34921
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66327426");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34921");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCuj83344.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/28");

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

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.8)"))
  fixed_ver = "8.4(7)8";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.2)"))
  fixed_ver = "9.0(4)2";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if CIFS is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s+nbns-server ", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because CIFS does not appear to be enabled.");
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
