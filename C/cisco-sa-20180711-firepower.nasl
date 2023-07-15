#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111211);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2018-0370",
    "CVE-2018-0383",
    "CVE-2018-0384",
    "CVE-2018-0385"
  );
  script_bugtraq_id(
    104725,
    104726,
    104727,
    104728
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi09219");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi29845");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh70130");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh84511");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi36434");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180711-firepower-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180711-firesight-file-bypass");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180711-firesight-url-bypass");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180711-firepwr-ssl-dos");
  script_xref(name:"IAVA", value:"2018-A-0236-S");

  script_name(english:"Cisco Firepower and FireSIGHT Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Firepower Threat Defense Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat
Defense Software is affected by one or more vulnerabilities. Please
see the included Cisco BIDs and the Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180711-firepower-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b62bc4eb");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180711-firesight-file-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fee237aa");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180711-firesight-url-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f84e9916");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180711-firepwr-ssl-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ad82087");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi09219");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi29845");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh70130");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh84511");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi36434");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvi09219, CSCvi29845, CSCvh70130, CSCvh84511, and CSCvi36434.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

VULN = FALSE;
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");
if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

if (
  fdm_ver[1] == "5.4.0" ||
  fdm_ver[1] == "6.0.0" ||
  fdm_ver[1] == "6.1.0" ||
  fdm_ver[1] == "6.1.0.7" ||
  fdm_ver[1] == "6.2.0" ||
  fdm_ver[1] == "6.2.0.5" ||
  fdm_ver[1] == "6.2.1" ||
  fdm_ver[1] == "6.2.2" ||
  fdm_ver[1] == "6.2.2.1" ||
  fdm_ver[1] == "6.2.2.2" ||
  fdm_ver[1] == "6.2.3" ||
  fdm_ver[1] == "6.3.0"
)  vuln = TRUE;

# Cisco hasn't stated a fix, but lists the latest versions as vuln.
if (vuln)
{
  report =
  '\n  Bug               : CSCvi09219, CSCvi29845, CSCvh70130, CSCvh84511, and CSCvi36434' +
  '\n  Installed version : ' + fdm_ver[1] +
  '\n  Fix               : ' +"See advisory";
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
} else audit(AUDIT_HOST_NOT, "affected");

