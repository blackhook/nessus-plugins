#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:017
#


if ( ! defined_func("bn_random") ) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(13833);
 script_version("1.14");
 script_cve_id("CVE-2004-0554");
 
 name["english"] = "SuSE-SA:2004:017: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2004:017 (kernel).


The Linux kernel is vulnerable to a local denial-of-service attack.
By using a C program it is possible to trigger a floating point
exception that puts the kernel into an unusable state.
To execute this attack a malicious user needs shell access to the
victim's machine.
The severity of this bug is considered low because local denial-of-
service attacks are hard to prevent in general.
Additionally the bug is limited to x86 and x86_64 architecture." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_17_kernel.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"kernel-source-2.4.18.SuSE-299", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.18-299", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-299", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-299", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-299", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-226", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-226", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-226", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-226", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-226", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-113", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-113", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-113", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-113", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-113", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-226", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-226", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-226", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-226", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-226", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-226", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.75", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.75", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.75", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.75", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0554", value:TRUE);
}
