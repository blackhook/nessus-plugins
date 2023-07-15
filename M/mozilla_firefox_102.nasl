#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17603);
 script_version("1.27");

 script_cve_id("CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0402");
 script_bugtraq_id(12672, 12881, 12884, 12885);

 script_name(english:"Firefox < 1.0.2 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Firefox contains various security issues that
may allow an attacker to impersonate a website and to trick a user
into accepting and executing arbitrary files or to cause a heap
overflow in the FireFox process and execute arbitrary code on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-30/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-31/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-32/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/23");
 script_cvs_date("Date: 2018/07/16 14:09:14");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/03/23");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

 script_summary(english:"Determines the version of Firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

#
include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0.2', severity:SECURITY_WARNING);