#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25820);
  script_version("1.22");

  script_cve_id("CVE-2007-3844", "CVE-2007-3845", "CVE-2007-4041");
  script_bugtraq_id(25053, 25142);

  script_name(english:"Firefox < 2.0.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox allows unescaped URIs to be passed to
external programs, which could lead to execution of arbitrary code on
the affected host subject to the user's privileges, and could also
allow privilege escalation attacks against addons that create
'about:blank' windows and populate them in certain ways." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-26/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-27/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(78);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/30");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/07/30");
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

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.6', severity:SECURITY_HOLE);