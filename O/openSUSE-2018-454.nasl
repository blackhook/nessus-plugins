#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-454.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109751);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-5754", "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-7540", "CVE-2018-7541", "CVE-2018-7542", "CVE-2018-8897");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVB", value:"2018-B-0057-S");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2018-454) (Meltdown)");
  script_summary(english:"Check for the openSUSE-2018-454 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen to version 4.9.2 fixes several issues.

This feature was added :

  - Added script, udev rule and systemd service to watch for
    vcpu online/offline events in a HVM domU. They are
    triggered via 'xl vcpu-set domU N'

These security issues were fixed :

  - CVE-2018-8897: Prevent mishandling of debug exceptions
    on x86 (XSA-260, bsc#1090820)

  - Handle HPET timers in IO-APIC mode correctly to prevent
    malicious or buggy HVM guests from causing a hypervisor
    crash or potentially privilege escalation/information
    leaks (XSA-261, bsc#1090822)

  - Prevent unbounded loop, induced by qemu allowing an
    attacker to permanently keep a physical CPU core busy
    (XSA-262, bsc#1090823)

  - CVE-2018-10472: x86 HVM guest OS users (in certain
    configurations) were able to read arbitrary dom0 files
    via QMP live insertion of a CDROM, in conjunction with
    specifying the target file as the backing file of a
    snapshot (bsc#1089152).

  - CVE-2018-10471: x86 PV guest OS users were able to cause
    a denial of service (out-of-bounds zero write and
    hypervisor crash) via unexpected INT 80 processing,
    because of an incorrect fix for CVE-2017-5754
    (bsc#1089635).

  - CVE-2018-7540: x86 PV guest OS users were able to cause
    a denial of service (host OS CPU hang) via
    non-preemptable L3/L4 pagetable freeing (bsc#1080635).

  - CVE-2018-7541: Guest OS users were able to cause a
    denial of service (hypervisor crash) or gain privileges
    by triggering a grant-table transition from v2 to v1
    (bsc#1080662).

  - CVE-2018-7542: x86 PVH guest OS users were able to cause
    a denial of service (NULL pointer dereference and
    hypervisor crash) by leveraging the mishandling of
    configurations that lack a Local APIC (bsc#1080634).

These non-security issues were fixed :

  - bsc#1087252: Update built-in defaults for xenstored in
    stubdom, keep default to run xenstored as daemon in dom0

  - bsc#1087251: Preserve xen-syms from xen-dbg.gz to allow
    processing vmcores with crash(1) 

  - bsc#1072834: Prevent unchecked MSR access error This
    update was imported from the SUSE:SLE-12-SP3:Update
    update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090823"
  );
  # https://features.opensuse.org/324965
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"xen-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-debugsource-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-devel-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-doc-html-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-libs-debuginfo-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-debuginfo-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-4.9.2_04-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xen-tools-domU-debuginfo-4.9.2_04-19.2") ) flag++;

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
