#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:042
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13810);
 script_version("1.11");
 
 name["english"] = "SUSE-SA:2003:042: mysql";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:042 (mysql).


A remotely exploitable buffer overflow within the authentication code
of MySQL has been reported. This allows remote attackers who have
access to the 'User' table to execute arbitrary commands as mysql user.
The list of affected packages is as follows:
mysql, mysql-client, mysql-shared, mysql-bench, mysql-devel, mysql-Max.
In this advisory the MD5 sums for the mysql, mysql-shared and mysql-devel
packages are listed.

To be sure the update takes effect you have to restart the MySQL server
by executing the following command as root:

/usr/sbin/rcmysql restart

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_042_mysql.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the mysql package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-3.23.37-62", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-shared-3.23.37-62", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.37-62", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-3.23.44-28", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-shared-3.23.44-28", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.44-28", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-3.23.48-81", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-shared-3.23.48-81", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.48-81", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-3.23.52-106", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-shared-3.23.52-106", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.52-106", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-3.23.55-22", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-shared-3.23.55-22", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.55-22", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
