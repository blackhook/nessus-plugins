#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23928);
  script_version("1.17");

  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500",
                "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504",
                "CVE-2006-6505");
  script_bugtraq_id(21668);

  script_name(english:"SeaMonkey < 1.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-68/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-69/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-70/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-71/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-72/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-73/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-74/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.0.7 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/19");
 script_cvs_date("Date: 2018/07/27 18:38:15");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/11/08");
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

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.0.7', severity:SECURITY_HOLE);