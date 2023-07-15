#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24701);
  script_version("1.29");
  script_cvs_date("Date: 2018/07/16 14:09:14");

  script_cve_id(
    "CVE-2006-6077",
    "CVE-2007-0008",
    "CVE-2007-0009",
    "CVE-2007-0775",
    "CVE-2007-0776",
    "CVE-2007-0777",
    "CVE-2007-0778",
    "CVE-2007-0779",
    "CVE-2007-0780",
    "CVE-2007-0800",
    "CVE-2007-0801",
    "CVE-2007-0802",
    "CVE-2007-0981",
    "CVE-2007-0994",
    "CVE-2007-0995",
    "CVE-2007-0996",
    "CVE-2007-1092"
  );
  script_bugtraq_id(21240, 22396, 22566, 22679, 22694, 22826);

  script_name(english:"Firefox < 1.5.0.10 / 2.0.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, some of which could lead to execution of arbitrary code on the
affected host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-02/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-05/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-06/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-07/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-08/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-09/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 1.5.0.10 / 2.0.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/24");

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


include("global_settings.inc");
include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 10)
    )
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 2)
) security_hole(get_kb_item("SMB/transport"));
