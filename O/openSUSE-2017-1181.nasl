#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1181.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104085);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15591", "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595", "CVE-2017-5526");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2017-1181)");
  script_summary(english:"Check for the openSUSE-2017-1181 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues :

These security issues were fixed :

  - CVE-2017-5526: The ES1370 audio device emulation support
    was vulnerable to a memory leakage issue allowing a
    privileged user inside the guest to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1059777)

  - CVE-2017-15593: Missing cleanup in the page type system
    allowed a malicious or buggy PV guest to cause DoS
    (XSA-242 bsc#1061084)

  - CVE-2017-15592: A problem in the shadow pagetable code
    allowed a malicious or buggy HVM guest to cause DoS or
    cause hypervisor memory corruption potentially allowing
    the guest to escalate its privilege (XSA-243
    bsc#1061086)

  - CVE-2017-15594: Problematic handling of the selector
    fields in the Interrupt Descriptor Table (IDT) allowed a
    malicious or buggy x86 PV guest to escalate its
    privileges or cause DoS (XSA-244 bsc#1061087)

  - CVE-2017-15591: Missing checks in the handling of DMOPs
    allowed malicious or buggy stub domain kernels or tool
    stacks otherwise living outside of Domain0 to cause a
    DoS (XSA-238 bsc#1061077)

  - CVE-2017-15589: Intercepted I/O write operations with
    less than a full machine word's worth of data were not
    properly handled, which allowed a malicious unprivileged
    x86 HVM guest to obtain sensitive information from the
    host or other guests (XSA-239 bsc#1061080)

  - CVE-2017-15595: In certain configurations of linear page
    tables a stack overflow might have occured that allowed
    a malicious or buggy PV guest to cause DoS and
    potentially privilege escalation and information leaks
    (XSA-240 bsc#1061081)

  - CVE-2017-15588: Under certain conditions x86 PV guests
    could have caused the hypervisor to miss a necessary TLB
    flush for a page. This allowed a malicious x86 PV guest
    to access all of system memory, allowing for privilege
    escalation, DoS, and information leaks (XSA-241
    bsc#1061082)

  - CVE-2017-15590: Multiple issues existed with the setup
    of PCI MSI interrupts that allowed a malicious or buggy
    guest to cause DoS and potentially privilege escalation
    and information leaks (XSA-237 bsc#1061076)

  - bsc#1055321: When dealing with the grant map space of
    add-to-physmap operations, ARM specific code failed to
    release a lock. This allowed a malicious guest
    administrator to cause DoS (XSA-235)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061087"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"xen-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-debugsource-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-devel-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-doc-html-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-debuginfo-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-debuginfo-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-4.9.0_14-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-debuginfo-4.9.0_14-10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debugsource / xen-devel / xen-doc-html / xen-libs / etc");
}
