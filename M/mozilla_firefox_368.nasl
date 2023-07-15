#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47829);
  script_version("1.10");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id("CVE-2010-2755");
  script_bugtraq_id(41933);
  script_xref(name:"Secunia", value:"40720");

  script_name(english:"Firefox 3.6.7 Remote Code Execution");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that may allow
execution of remote code.");

  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is 3.6.7.  This version is
potentially affected by a memory corruption vulnerability that could
lead to arbitrary code execution.  (MFSA 2010-48)");
  
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-48/");
  #https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-3.6/#firefox3.6.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f416d76e");  
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 3.6.8 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.8', min:'3.6.7', severity:SECURITY_HOLE);