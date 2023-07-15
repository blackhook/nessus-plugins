#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2812-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104098);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595", "CVE-2017-5526");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2017:2812-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues: These security issues were
fixed :

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

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15588/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15589/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15590/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15592/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15593/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15594/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15595/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5526/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172812-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fabc83fc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-xen-13320=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-xen-13320=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-xen-13320=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_21_3.0.101_0.47.106.5-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_21_3.0.101_0.47.106.5-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_21_3.0.101_0.47.106.5-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_21-45.11.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_21_3.0.101_0.47.106.5-45.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
