#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117917);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2018-15383", "CVE-2018-15390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh77456");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj89470");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-ftd-inspect-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-asa-dma-dos");

  script_name(english:"Cisco Firepower Threat Defense Software Multiple DoS Vulnerabilities (cisco-sa-20181003-ftd-inspect-dos, cisco-sa-20181003-asa-dma-dos)");
  script_summary(english:"Checks the Cisco Firepower Threat Defense Software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat
Defense Software is affected by multiple DoS vulnerabilities. Please
see the included Cisco BIDs and the Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-ftd-inspect-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc766c18");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-asa-dma-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41a6402c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh77456");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj89470");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvh77456 and CSCvj89470.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fix = '';
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");
if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

# 6.0, 6.0.1, 6.1.0 < 6.1.0.7
if (ver_compare(minver:'6.0', fix:'6.1.0.7', ver:fdm_ver[1], strict:FALSE) < 0)
  fix = '6.1.0.7';
# 6.2.0 < 6.2.0.7
else if (ver_compare(minver:'6.2.0', fix:'6.2.0.7', ver:fdm_ver[1], strict:FALSE) < 0)
  fix = '6.2.0.7';
# 6.2.1 < 6.2.2.5
else if (ver_compare(minver:'6.2.1', fix:'6.2.2.5', ver:fdm_ver[1], strict:FALSE) < 0)
  fix = '6.2.2.5';
# 6.2.3 < 6.2.3.4
else if (ver_compare(minver:'6.2.3', fix:'6.2.3.4', ver:fdm_ver[1], strict:FALSE) < 0)
  fix = '6.2.3.4';

if (!empty_or_null(fix))
{
  report =
    '  Bugs              : CSCvh77456, CSCvj89470' +
  '\n  Installed version : ' + fdm_ver[1] +
  '\n  Fix               : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_HOST_NOT, "affected");

