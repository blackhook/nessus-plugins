#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:027
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(18113);
 script_version("1.11");
 script_cve_id("CVE-2005-0247");
 
 name["english"] = "SUSE-SA:2005:027: postgresql";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:027 (postgresql).


Several problems were identified and fixed in the PostgreSQL
database server.

Multiple buffer overflows in the low level parsing routines may
allow attackers to execute arbitrary code via:

(1) a large number of variables in a SQL statement being handled by
the read_sql_construct() function,

(2) a large number of INTO variables in a SELECT statement being
handled by the make_select_stmt function,

(3) a large number of arbitrary variables in a SELECT statement being
handled by the make_select_stmt function, and

(4) a large number of INTO variables in a FETCH statement being
handled by the make_fetch_stmt function.


This is tracked by the Mitre CVE ID CVE-2005-0247." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_27_postgresql.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_cwe_id(119);




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the postgresql package";
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
if ( rpm_check( reference:"postgresql-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.3.9-6", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-test-7.3.9-7", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.7-0.5", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-7.4.7-0.3", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-pl-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.0.1-6", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"postgresql-", release:"SUSE8.2")
 || rpm_exists(rpm:"postgresql-", release:"SUSE9.0")
 || rpm_exists(rpm:"postgresql-", release:"SUSE9.1")
 || rpm_exists(rpm:"postgresql-", release:"SUSE9.2")
 || rpm_exists(rpm:"postgresql-", release:"SUSE9.3") )
{
 set_kb_item(name:"CVE-2005-0247", value:TRUE);
}
