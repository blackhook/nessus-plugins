#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(14192);
 script_version("1.20");

 script_cve_id("CVE-2004-0722");
 script_bugtraq_id(10843);

 script_name(english:"Mozilla SOAPParameter Object Constructor Overlow");
 script_summary(english:"Determines the version of Mozilla");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
an integer overflow vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The Mozilla web browser is installed on the remote host.

The remote version of this software has an integer overflow
vulnerability in the SOAPParameter object constructor. This could
result in arbitrary code execution.

A remote attacker could exploit this flaw by tricking a user into
viewing a maliciously crafted web page." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mozilla 1.7.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/08/02");
 script_cvs_date("Date: 2018/07/16 14:09:15");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Version");
 exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.7.1', severity:SECURITY_HOLE);
