#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31652);
  script_version("1.16");

  script_cve_id(
    "CVE-2007-4879", 
    "CVE-2008-1195", 
    "CVE-2008-1233", 
    "CVE-2008-1234", 
    "CVE-2008-1235",
    "CVE-2008-1236", 
    "CVE-2008-1237", 
    "CVE-2008-1238", 
    "CVE-2008-1240", 
    "CVE-2008-1241"
  );
  script_bugtraq_id(28448);

  script_name(english:"Firefox < 2.0.0.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - A series of vulnerabilities that allow for JavaScript 
    privilege escalation and arbitrary code execution.

  - Several stability bugs leading to crashes which, in
    some cases, show traces of memory corruption.

  - An HTTP Referer spoofing issue with malformed URLs.

  - A privacy issue with SSL client authentication.

  - Web content fetched via the 'jar:' protocol can use 
    Java via LiveConnect to open socket connections to 
    arbitrary ports on the localhost.

  - It is possible to have a background tab create a 
    borderless XUL pop-up in front of the active tab 
    in the user's browser." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-14/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-15/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-16/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-17/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-18/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-19/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.13 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(59, 79, 94, 287, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/03/25");
 script_cvs_date("Date: 2018/07/16 14:09:14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.13', severity:SECURITY_HOLE);