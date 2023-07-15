#TRUSTED 05c0df44d3a63b83cae4b4df582e17f7a4bb81065d6f7226ec08315303aeb2b910087e6761ba819616b2b6cd0694891a6e3979204d2e4c15558fc408edbaacd7505fcc087f80a3939afe0cc56ca564e2b70cb39af47f98f84757dc7c89544888fecc97c5fc8c4260a3d17204ad36bbc71ac434614510f013522cc7239f944309a889f43f74383589ef0ec96a2b5ee7cf769b6aae7b4b369ae3ba07c3f9bbc9905d4c3044d8aac509c5a95614584e74b91f9a59833e3888a7818f921a250ba0e8ca67fc922a7920670ab062e30be6374e96f87416b5c2c29c696ea765c1f60a59791c98c1fc88aec335335199af9866b4b335ccd0588495234b795d6c53cb69cfa1b584bbee0f7cbccf4152659f77eabb59cf3dc13ec621ef5d5df42e09f5f90179bf8c639161fa58b7d3685d9214ecb913c329f6f38f39b0abbcca7ccdb559e92450e9c478779983c0e959b4b9baa6990682c76c450af1c1df204e0be1e520fdfa85defcbf49cf25f42e5818209b0601ede52ce425f909fd1dcb2b22431dbfdc2fac1cd109e6292e69811351dbb6dd4ba8b0ce721fceef0e7b71c0e9cb074627d561035f41a11784c66dfe4f9b66f168c180d1a93e16222ea59407c3c4d73338a4312e3e98228eb17371d9e8bd1b03010ed9b88b2f61aedd807431e2c67425e4b089fe0a81b5c68e953bddb448a452a3ca0dd3f3fbc354b81d783635f2df405c
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102499);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6752");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd47888");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170802-asa2");

  script_name(english:"Cisco Adaptive Security Appliance Username Enumeration Information Disclosure Vulnerability (CSCvd47888)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a vulnerability in the web-based management
interface of Cisco Adaptive Security Appliance (ASA) that could allow
an authenticated, remote attacker to determine valid usernames.

The vulnerability is due to the interaction between Lightweight
Directory Access Protocol (LDAP) and SSL Connection Profile when they
are configured together. An attacker could exploit the vulnerability
by performing a username enumeration attack to the IP address of the
device. An exploit could allow the attacker to determine valid
usernames.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-asa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68b260d1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170802-asa2.

The ASA administrator can use the following command to disable
on-board password management:

tunnel-group DefaultWEBVPNGroup general-attributes
no password-management");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])')
  audit(AUDIT_HOST_NOT, 'ASA 5500-X');

cbi = 'CSCvd47888';
fix = NULL;

if (version == "9.3(3)")
  fix = "See advisory";

else if (version == "9.6(2)")
  fix = "9.6(3.2)";

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA", version);

override = FALSE;
vuln = FALSE;

cmds = make_list();

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check if password-management is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"password-management", string:buf))
      cmds = make_list(cmds, "show running-config");
      vuln = TRUE;
    }
  else if (cisco_needs_enable(buf)) override = TRUE;
  }

if (!vuln && !override)
  audit(AUDIT_HOST_NOT, "affected because on-board password management is not enabled");

if (vuln || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    override : override,
    bug_id   : cbi,
    fix      : fix,
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
