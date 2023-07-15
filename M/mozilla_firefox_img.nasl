#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15712);
 script_version("1.18");

 script_cve_id("CVE-2005-0141", "CVE-2005-0143", "CVE-2005-0144", "CVE-2005-0145", "CVE-2005-0146",
               "CVE-2005-0147", "CVE-2005-0150");
 script_bugtraq_id(11648,12407);

 script_name(english:"Firefox < 1.0.0 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Firefox");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Firefox is earlier than 1.0.0.  Such
versions have multiple vulnerabilities that could result in
a denial of service, local file disclosure, or password
disclosure.  These vulnerabilities are due to the fact that
Firefox does handle the <IMG> tag correctly." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 1.0.0 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/30");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/11/09");
 script_cvs_date("Date: 2018/07/16 14:09:15");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

include("mozilla_version.inc");

port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.0', severity:SECURITY_WARNING);
