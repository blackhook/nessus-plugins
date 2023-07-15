#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25842);
  script_version("1.21");

  script_cve_id("CVE-2007-3844", "CVE-2007-3845", "CVE-2007-4041");
  script_bugtraq_id(25053, 25142);

  script_name(english:"SeaMonkey < 1.1.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey allows unescaped URIs to be passed to
external programs, which could lead to execution of arbitrary code on the
affected host subject to the user's privileges, and could also allow
privilege escalation attacks against addons that create 'about:blank'
windows and populate them in certain ways." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-23/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-26/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-27/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(78);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/30");
 script_cvs_date("Date: 2018/07/27 18:38:15");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.1.4', severity:SECURITY_HOLE);