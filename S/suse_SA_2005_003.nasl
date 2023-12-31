#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:003
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(16307);
 script_version("1.11");
 script_cve_id("CVE-2004-1235", "CVE-2005-0001");
 
 name["english"] = "SUSE-SA:2005:003: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:003 (kernel).



Several exploitable security problems were identified and fixed in
the Linux kernel, the core of every SUSE Linux product.


- Due to missing locking in the sys_uselib system call a local attacker
can gain root access. This was found by Paul Starzetz and is tracked
by the Mitre CVE ID CVE-2004-1235.


- Paul Starzetz also found a race condition in SMP page table handling
which could lead to a local attacker gaining root access on SMP
machines. This is tracked by the Mitre CVE ID CVE-2005-0001.


- A local denial of service was found in the auditing subsystem which
have lead a local attacker crashing the machine. This was reported
and fixed by Redhat.


- The sendmsg / cmsg fix from the previous kernel update was faulty
on 64bit systems with 32bit compatibility layer and could lead to
32bit applications not working correctly on those 64bit systems.


- The smbfs security fixes from a before-previous kernel update were
faulty for some file write cases.


- A local denial of service with Direct I/O access to NFS file systems
could lead a local attacker to crash a machine with NFS mounts.


- grsecurity reported a signed integer problem in the SCSI ioctl
handling which had a missing boundary check.
Due to C language specifics, this evaluation was not correct and
there actually is no problem in this code.
The signed / unsigned mismatch was fixed nevertheless.


- Several more small non security problems were fixed.


NOTE: Two days ago we released the Service Pack 1 for the SUSE Linux
Enterprise Server 9. This kernel update contains fixes for the SUSE
Linux Enterprise Server 9 GA version kernel line.

A fix for the Service Pack 1 version line will be available shortly." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_03_kernel.html" );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/03");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"kernel-source-2.4.21-273", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-273", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-273", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-273", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-273", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-129", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-129", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-129", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-129", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-129", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-273", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-273", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-273", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-273", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-273", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-273", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.111.30", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.8-24.11", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.8-24.11", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8-24.11", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.8-24.11", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.8-24.11", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.2") )
{
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
 set_kb_item(name:"CVE-2005-0001", value:TRUE);
}
