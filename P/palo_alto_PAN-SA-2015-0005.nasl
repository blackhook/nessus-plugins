#TRUSTED 3b9967a5af158d8b2d957ae175f66d2b260bda850ecd8870ac325af00ae6859fbf5f5fc011f6a53961593ec33babcdd63862cece3d19bcae8f33331def7be6b92f0ba7e381c2e41117846474057b2d594436027c2c1a7c85878d46a910186174f63f0c75bdb2e96ed27cbd17acc0ca6518319f922a714d4eff7a42ead55fe7f6430da2fa18a1bd156b4ab039199662fcf78c8a59e67d3f05ffd88ae7d133753c3fb0f13342e2991f68c58601c6808ed60db336f192bfb0f747dfbf37ebae9fc3843354ff8fabbfbb647042afb7ed8d418a2d5d1e1eb57f3557d8b9183425ae1a0eec2cd2e3870766e7e0f885d8e609c70fe83789b0a5df5b339a227c16fb4e3abe902ddde92e0026a0ed0a74c384e9e3cf37bcc0c218d2eaabdcd5434374077458edc2a6e945764309404402301d82e4fa8f088eefd410ebc2e58ea2b71959e21391382ecb5cc494c8d80888c27a18280bb381e5ba5eaab4573a24f6c99155b55d755d86ce350dce7681cf5bb5258abf069c07d80e743c9913c2c8a2c7132a834c5534d3ff12fa6e64385507fb2aac1573474c56e5feddc76ecb80528c2caea7c9e4b61a81b23e4f41165f7a62913c83583004f44f6aa26359e79c05beebb3bb4d0fc9081729c2f4871abfaa989408239fddd38611d5297b818a757deb7db2dc408166cca1c619fe31241d9e0ea76e90c266dfed859172bd27b25f64448fd461
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85535);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");


  script_name(english:"Palo Alto Networks PAN-OS 7.0.0 LDAP Authentication Bypass (PAN-SA-2015-0005)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Palo Alto Networks PAN-OS version 7.0.0. It
is, therefore, affected by an unspecified flaw in the LDAP
authentication process. A remote attacker can exploit this to bypass
authentication checks presented by the captive portal component or the
device management interfaces.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS 7.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
has_ldap = FALSE;
fix = FALSE;

# Advisory is very specific : only 7.0.0 is affected
if(version == "7.0.0")
  fix = "7.0.1";
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# If we're paranoid, check for an LDAP profile on the device
if(report_paranoia < 2)
{
  cmd = "show config running xpath shared/authentication-profile | match 'ldap'";
  buf = ssh_open_connection();
  if(!buf)
    audit(AUDIT_FN_FAIL, "ssh_open_connection");
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE, no53:TRUE);
  if("ldap" >< buf)
    has_ldap = TRUE;
  ssh_close_connection();
}
else # Otherwise assume the risk of FP
  has_ldap = TRUE;

if(fix && has_ldap)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
