#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23997);
  script_version("1.21");
  script_cvs_date("Date: 2019/05/16 10:38:54");

  script_cve_id("CVE-2007-0125");
  script_bugtraq_id(21901);

  script_name(english:"Kaspersky Anti-Virus PE File Handling DoS");
  script_summary(english:"Checks date of virus signatures");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an antivirus application that is
prone to a denial of service attack." );
  script_set_attribute(attribute:"description", value:
"The version of Kaspersky Anti-Virus installed on the remote host is
affected by a denial of service issue that can be triggered with a
specially crafted PE (portable executable) file to send the scanning
engine into an infinite loop and prevent scanning of other files." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=459
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34269a05" );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/456110/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Update the virus signatures to 01/02/2007 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0125");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/09");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("Antivirus/Kaspersky/sigs");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# sigs format : MM/DD/YYYY
kb_sigs = get_kb_item_or_exit("Antivirus/Kaspersky/sigs");

if (kb_sigs == "unknown")
  audit(AUDIT_UNKNOWN_APP_VER, "the Kaspersky anti-virus signatures (unknown)");

if (kb_sigs !~ "^[0-9]+\/[0-9]+\/[0-9]+$")
  audit(AUDIT_UNKNOWN_APP_VER, "the Kaspersky anti-virus signatures (bad format)");

# Convert to YYYY/MM/DD
sigs = ereg_replace(string:kb_sigs , pattern:"^([0-9]+)\/([0-9]+)\/([0-9]+)$", replace:"\3.\1.\2");

# Ver check against YYYY/MM/DD
if (ver_compare(fix:"2007.1.2", ver:sigs) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report = '  Signatures date : ' + kb_sigs +'\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Kaspersky anti-virus signatures", kb_sigs);
