#TRUSTED 256adf63d2773a7052422db50b5f1c50b0fa64224a143cc330badb3cd4952d23684e47b4b31cf5ee80149abec656fe4dd3bc78329e5d6e5a567b2fe530364699e07542b97dd472ebeb18794b78bb6f843ff25770e638c8d53c7d6630f1f020532c471ee8c1aa8f42cdcf1e8a043f7f80eb0a9db76e4aa58163763bb4290cf5ad0b8055ce6cb9a089b6b38c51b1422462b072e566403423826752b8ecc482b04c051f455515dee68e34c4bb855076f4e73462926d32c4c8569ee92b1dc6ede33e8ef8678ea8a7b04b7eeff01d4dbd73e1b7563b8f6f6454509aa9f67d2add6efe0952aa0ff7be429fd5eb999322694cc7b7527885935b123253fce012531c9ec0d08331ab87b86cddd711456c3d6488f09c297d7fc1c05de43e2ea8b073f705fe2f8e53109416189c5968f860952139795aad73123aa06529ab8323c4901917cda84134697be2a0886810481f6414b4d53bec34026d4be36560aaa31acce0a576fd2a6e941c9e7bac45227bd03a76e8665d06f20ac9b773b095544b5d9d8e4e1daf9d1e54dba9247e6b97f8cf2f9614e98634ec0e92eb78f1f5dc717ccf0dd1a062489ffe8edd0f7e6370ef2e0237bd97cd3ca75a3f16cda2f48607e9d7a420f3a945448e93447c68f4319841c0c4cb45dc4ddfaa404d97cf70b771b65871f2276fa40e1fc1c32a1b6838bfd5ac53c0e3f3c937d34dbbb58b7eb6b43717b403d1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99372);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3879");
  script_bugtraq_id(96920);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy25824");
  script_xref(name:"IAVA", value:"2017-A-0096");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170315-nss1");

  script_name(english:"Cisco NX-OS Failed Authentication Handling Remote DoS (cisco-sa-20170315-nss1)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the remote login functionality due to improper
handling of failed authentication during login. An unauthenticated,
remote attacker can exploit this to cause Telnet or SSH to terminate.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-nss1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7a1d656");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy25824.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag = 0;
cbid = FALSE;

########################################
# Model 9k
########################################
if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "7.0(3)I3(1)"         ) flag = TRUE;
  else if(version == "8.3(0)CV(0.342)") flag = TRUE;
  else if(version == "8.3(0)CV(0.345)") flag = TRUE;
  cbid = "CSCuy25824";
}

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

# Check for telnet feature
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^(\s+)?feature telnet", string:buf) || !preg(multiline:TRUE, pattern:"^(\s+)?no feature ssh", string:buf))
    flag = TRUE;
  }
}
else if (cisco_needs_enable(buf)) override = TRUE;

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbid
  );
}
else audit(AUDIT_HOST_NOT, "affected");
