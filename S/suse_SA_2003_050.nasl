#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:050
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13818);
 script_version("1.17");
 script_cve_id("CVE-2003-0962");
 
 name["english"] = "SuSE-SA:2003:050: rsync";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:050 (rsync).


The rsync suite provides client and server tools to easily support an
administrator keeping the files of different machines in sync.
In most private networks the rsync client tool is used via SSH to fulfill
his tasks. In an open environment rsync is run in server mode accepting
connections from many untrusted hosts with, but mostly without,
authentication.
The rsync server drops its root privileges soon after it was started and
per default creates a chroot environment.
Due to insufficient integer/bounds checking in the server code a heap
overflow can be triggered remotely to execute arbitrary code. This code
does not get executed as root and access is limited to the chroot
environment. The chroot environment maybe broken afterwards by abusing
further holes in system software or holes in the chroot setup.

Your are not vulnerable as long as you do not use rsync in server mode
or you use authentication to access the rsync server.

As a temporary workaround you can disable access to your rsync server for
untrusted parties, enable authentication or switch back to rsync via SSH.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_50_rsync.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the rsync package";
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
if ( rpm_check( reference:"rsync-2.4.6-499", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.4.6-499", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.5-258", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.6-193", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.6-193", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"SUSE7.3")
 || rpm_exists(rpm:"rsync-", release:"SUSE8.0")
 || rpm_exists(rpm:"rsync-", release:"SUSE8.1")
 || rpm_exists(rpm:"rsync-", release:"SUSE8.2")
 || rpm_exists(rpm:"rsync-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2003-0962", value:TRUE);
}
