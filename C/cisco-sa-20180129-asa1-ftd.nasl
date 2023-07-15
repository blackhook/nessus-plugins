#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106630);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_cve_id("CVE-2018-0101");
  script_bugtraq_id(102845);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg35618");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh79732");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh81737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh81870");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180129-asa1");
  script_xref(name:"IAVA", value:"0001-A-0011-S");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Adaptive Security Appliance Remote Code Execution and Denial of Service Vulnerability (cisco-sa-20180129-asa1)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD)
software installed on the remote host is affected by a vulnerability
in the XML parser that can allow a remote, unauthenticated attacker
to execute arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180129-asa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?118d2746");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg35618");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh79732");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh81737");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh81870");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed version referenced in the Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0101");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/show_ver", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');

app = "Cisco Firepower Threat Defense";
fix = NULL;

ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(ver)) audit(AUDIT_HOST_NOT, app);

ver = ver[1];

if (ver =~ "^[0-5]\." || ver =~ "^6\.0\.[01]($|\.)")
  fix = "6.0.1.5";
else if (ver =~ "^6\.1\.0($|\.)")
  fix = "6.1.0.7";
else if (ver =~ "^6\.2\.0($|\.)")
  fix = "6.2.0.5";
else if (ver =~ "^6\.2\.[12]($|\.)")
  fix = "6.2.2.2";
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Bugs              : CSCvg35618, CSCvh79732, CSCvh81737, CSCvh81870' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
