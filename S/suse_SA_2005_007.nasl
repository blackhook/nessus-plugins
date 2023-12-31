#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:007
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(16454);
 script_version("1.11");
 script_cve_id("CVE-2004-1143", "CVE-2004-1177", "CVE-2005-0202");
 
 name["english"] = "SUSE-SA:2005:007: mailman";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:007 (mailman).


Mailman is a flexible mailing list management tool. It provides
mail controlled subscription front ends and also includes CGI scripts
to handle subscription, moderation and archive retrieval and other
options.

Due to incomplete input validation the 'private' CGI script which
handles archive retrieval could be used to read any file on the
system, including the configuration database of the mailman lists
which include passwords in plain text. A remote attacker just needs
a valid account on one mailing list managed by this mailman instance.

This update fixes this problem and is tracked under the Mitre CVE
ID CVE-2005-0202.

Please see section (3), 'special instructions and notes'.

Our previous mailman update (only announced in the SUSE Summary Report)
additionally fixed the following two security problems:
- a cross site scripting problem (CVE-2004-1177)
- too weak auto generated passwords (CVE-2004-1143)

This previous security fix requires the additional 'python-xml' RPM
which was not required before." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_07_mailman.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the mailman package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mailman-2.1.1-110", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.2-93", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.4-83.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-5.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mailman-", release:"SUSE8.2")
 || rpm_exists(rpm:"mailman-", release:"SUSE9.0")
 || rpm_exists(rpm:"mailman-", release:"SUSE9.1")
 || rpm_exists(rpm:"mailman-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1143", value:TRUE);
 set_kb_item(name:"CVE-2004-1177", value:TRUE);
 set_kb_item(name:"CVE-2005-0202", value:TRUE);
}
