#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22371);
  script_version("1.29");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566",
                "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
  script_bugtraq_id(19488, 19534, 20042);

  script_name(english:"SeaMonkey < 1.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis", value:"A web browser on the remote host is prone to multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which could lead to execution of arbitrary code on the affected
host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-57/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-60/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-61/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-64/");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 1.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 119, 264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.0.5', severity:SECURITY_HOLE);
