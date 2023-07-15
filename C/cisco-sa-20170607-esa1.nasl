#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101264);
  script_version("1.4");
  script_cvs_date("Date: 2019/01/18 12:15:10");

  script_cve_id("CVE-2017-6671");
  script_bugtraq_id(98969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd34632");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170607-esa1");

  script_name(english:"Cisco AsyncOS for Email Security Appliance Attachment MIME Header Handling Filter Bypass (cisco-sa-20170607-esa1)");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco AsyncOS running on
the remote Cisco Email Security (ESA) appliance is affected by a
security bypass vulnerability in the email message scanning
functionality due to improper validation of emails with attachments
and a modified Multipurpose Internet Mail Extensions (MIME) header. An
unauthenticated, remote attacker can exploit this, via a malformed
email message with an attachment, to bypass configured security and
message filters.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-esa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01cafc9e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd34632");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd34632.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

ver_fixes = make_array(
  # affected ,  # fixed
  "9.7.1.066",  "9.8.1-015",
  "10.0.1.087", "10.0.2-020"
);

vuln = FALSE;
display_fix = NULL;
foreach affected (keys(ver_fixes))
{
  if (ver == affected)
  {
    display_fix = ver_fixes[affected];
    vuln = TRUE;
    break;
  }
}

if (isnull(display_fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

if (vuln)
{
  if (!local_checks) override = TRUE;

  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : display_ver,
    bug_id   : "CSCvd34632",
    fix      : display_fix
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);
