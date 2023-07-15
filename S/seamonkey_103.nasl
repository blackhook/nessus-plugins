#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22097);
  script_version("1.27");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802",
                "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806",
                "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810",
                "CVE-2006-3811", "CVE-2006-3812");
  script_bugtraq_id(19181, 19192, 19197);
  script_xref(name:"CERT", value:"655892");

  script_name(english:"SeaMonkey < 1.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which could lead to execution of arbitrary code on the affected
host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-44/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-45/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-47/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-48/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-53/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-55/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-56/");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 1.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox Navigator Object Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/25");

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

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.0.3', severity:SECURITY_HOLE);
