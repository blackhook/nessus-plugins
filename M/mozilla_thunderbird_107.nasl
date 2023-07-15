#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(19694);
  script_version("1.24");

  script_cve_id("CVE-2005-2871");
  script_bugtraq_id(14784);

  script_name(english:"Mozilla Thunderbird < 1.0.7 IDN URL Domain Name Overflow ");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of Mozilla Thunderbird suffers from several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Mozilla Thunderbird, an email client. 

The remote version of this software contains various security issues
that could allow an attacker to execute arbitrary code on the remote
host and to disguise URLs." );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/407704" );
 script_set_attribute(attribute:"see_also", value:"http://security-protocols.com/advisory/sp-x17-advisory.txt" );
 # http://web.archive.org/web/20100329062735/http://www.mozilla.org/security/idn.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11c09cbe" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Thunderbird 1.0.7 or disable IDN support in the browser
following the instructions in the vendor's advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/09/21");
 script_cvs_date("Date: 2018/11/15 20:50:27");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
script_end_attributes();

  script_summary(english:"Determines the version of Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Thunderbird/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] == 0 && ver[2] < 7)
) security_hole(get_kb_item("SMB/transport"));
