#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25349);
  script_version("1.22");

  script_cve_id(
    "CVE-2007-1004", 
    "CVE-2007-1362", 
    "CVE-2007-2867", 
    "CVE-2007-2868",
    "CVE-2007-2869", 
    "CVE-2007-2870", 
    "CVE-2007-2871"
  );
  script_bugtraq_id(22601, 22879, 24242);

  script_name(english:"Firefox < 1.5.0.12 / 2.0.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, one of which could lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=370555" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-12/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-13/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-14/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-16/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-17/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.12 / 2.0.0.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 94, 119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/16");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/05/30");
 script_cvs_date("Date: 2018/07/16 14:09:14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 12)
    ) 
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 4)
) security_hole(get_kb_item("SMB/transport"));
