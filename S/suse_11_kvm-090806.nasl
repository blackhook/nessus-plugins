#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(41416);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2287");

  script_name(english:"SuSE 11 Security Update : KVM (SAT Patch Number 1166)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KVM technology available as Technical Preview in SUSE Linux
Enterprise has been updated to version 0.10.5.

While a minor security issue was fixed, this mainly is a huge version
update.

Changelog :

  - 'info chardev' monitor command

  - automatic port allocation for vnc and similar

  - improved cdrom media change handling

  - scsi improvements

  - e1000 vlan offload

  - fix interrupt loss when injecting an nmi

  - SPT optimizations

  - x86 emulator improvements

  - fix amd->intel migration

  - enable virtio zero-copy (Mark McLoughlin)

  - uuid support

  - hpet support

  - '-drive serial=...' option

  - improved tsc handling (Marcelo Tosatti)

  - guest S3 sleep (Gleb Natapov)

  - '-no-kvm-pit-reinjection' option to improve timing on
    RHEL 3 era guests (Marcelo Tosatti)

  - fix xen-on-kvm

  - enable ac97 audio by default

  - add virtio-console device

  - fix rtc time drift on Windows (-rtc-td-hack option)

  - vnc improvements

  - fix kvmclock on hosts with unstable tsc (Gerd Hoffman)

  - fix cygwin on Windows x64

  - enable nested paging again And the KVM kernel module was
    upgraded to 2.6.30.1 :

  - check for CR3 set. (bnc#517671, CVE-2009-2287)

  - fix cpuid

  - fix guest reboot failures

  - fix interrupt loss when injecting an nmi

  - SPT optimizations

  - x86 emulator improvements

  - fix amd->intel migration

  - improved tsc handling (Marcelo Tosatti)

  - vnc improvements

  - fix kvmclock on hosts with unstable tsc (Gerd Hoffman)

  - fix cygwin on Windows x64"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=517671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2287.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1166.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kvm-78.0.10.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.25_0.1-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"kvm-kmp-pae-78.2.6.30.1_2.6.27.25_0.1-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kvm-78.0.10.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.25_0.1-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kvm-78.0.10.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.25_0.1-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"kvm-kmp-pae-78.2.6.30.1_2.6.27.25_0.1-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kvm-78.0.10.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"kvm-kmp-default-78.2.6.30.1_2.6.27.25_0.1-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
