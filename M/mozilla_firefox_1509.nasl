#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23930);
  script_version("1.16");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501",
                "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6506", "CVE-2006-6507");
  script_bugtraq_id(21668);

  script_name(english:"Firefox < 1.5.0.9 / 2.0.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which could lead to execution of arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-68/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-69/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-70/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-71/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-72/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-73/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-75/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-76/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.9 / 2.0.0.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/19");
 script_cvs_date("Date: 2018/07/16 14:09:14");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/08");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");
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
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 9)
    ) 
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1)
) security_hole(get_kb_item("SMB/transport"));
