#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103819);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12244", "CVE-2017-12245");
  script_bugtraq_id(101118, 101119);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02069");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd34776");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171004-ftd");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171004-fpsnort");

  script_name(english:"Cisco Firepower Detection Engine Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Firepower Threat Defense Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat
Defense Software is affected by one or more vulnerabilities. Please
see the included Cisco BIDs and the Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171004-ftd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?faa9474b");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171004-fpsnort
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da3cd01b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve02069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCve02069 and CSCvd34776.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12245");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

# Affected Models:
# 5500-X Series
if (
  model !~ '^55[0-9][0-9][WH]?-X'
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product model");

VULN = FALSE;
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");
if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

else if (fdm_ver[1] == "6.0.0" ||
         fdm_ver[1] == "6.0.1" ||
         fdm_ver[1] == "6.1.0" ||
         fdm_ver[1] == "6.1.0.1" ||
         fdm_ver[1] == "6.2.0" ||
         fdm_ver[1] == "6.2.1" ||
         fdm_ver[1] == "6.2.2" ||
         fdm_ver[1] == "6.2.3")
  vuln = TRUE;

# Cisco hasn't stated a fix, but lists the latest versions as vuln.
if (vuln)
{
  report =
  '\n  Bug               : CSCvd34776/CSCve02069' +
  '\n  Installed version : ' + fdm_ver[1] +
  '\n  Fix               : ' +"See advisory";
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
} else audit(AUDIT_HOST_NOT, "affected");

