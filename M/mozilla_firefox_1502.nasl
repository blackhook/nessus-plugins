#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21225);
  script_version("1.24");

  script_cve_id("CVE-2006-0748", "CVE-2006-1529", "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723",
                "CVE-2006-1724", "CVE-2006-1725", "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728",
                "CVE-2006-1729", "CVE-2006-1730");
  script_bugtraq_id(17516);

  script_name(english:"Firefox < 1.5.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks Firefox version number");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is using Firefox, an alternative web browser. 

The installed version of Firefox contains various security issues,
some of which may lead to execution of arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-20/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-22/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-23/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-24/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-25/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-27/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-28/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2006-29/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 189, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/13");
 script_cvs_date("Date: 2018/07/16 14:09:14");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/04/13");
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

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.5.0.1', severity:SECURITY_HOLE);