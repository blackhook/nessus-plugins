#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14242);
 script_version ("1.17");
 script_cve_id(
   "CVE-2002-1363",
   "CVE-2004-0421",
   "CVE-2004-0597",
   "CVE-2004-0598",
   "CVE-2004-0599"
 );
 script_bugtraq_id(10857);

 script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2004-08-09)");
 script_summary(english:"Check for Security Update 2004-08-09");
 
 script_set_attribute( attribute:"synopsis",  value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",   value:
"The remote host is missing Security Update 2004-08-09.

libpng is a library used for manipulating graphics files.  Several
buffer overflows have been discovered in libpng.  A remote attacker
could exploit these vulnerabilities by tricking a user into opening
a maliciously crafted PNG file, resulting in the execution of
arbitrary code." );
 # http://web.archive.org/web/20080915104713/http://support.apple.com/kb/HT1646?
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?210abeb5"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Install Security Update 2004-08-09."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/12/14");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/08/09");
 script_cvs_date("Date: 2018/07/14  1:59:35");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

#

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# MacOS X 10.2.x and 10.3.x only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.4\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-08-09", string:packages) ) security_warning(0);
}
