#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2292-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87495);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5156", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8215");
  script_bugtraq_id(73926);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:2292-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.51 to
receive various security and bugfixes.

Following features were added :

  - hwrng: Add a driver for the hwrng found in power7+
    systems (fate#315784).

Following security bugs were fixed :

  - CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in
    the Linux kernel did not validate attempted changes to
    the MTU value, which allowed context-dependent attackers
    to cause a denial of service (packet loss) via a value
    that is (1) smaller than the minimum compliant value or
    (2) larger than the MTU of an interface, as demonstrated
    by a Router Advertisement (RA) message that is not
    validated by a daemon, a different vulnerability than
    CVE-2015-0272. (bsc#955354)

  - CVE-2015-5156: The virtnet_probe function in
    drivers/net/virtio_net.c in the Linux kernel attempted
    to support a FRAGLIST feature without proper memory
    allocation, which allowed guest OS users to cause a
    denial of service (buffer overflow and memory
    corruption) via a crafted sequence of fragmented packets
    (bnc#940776).

  - CVE-2015-7872: The key_gc_unused_keys function in
    security/keys/gc.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) via crafted
    keyctl commands (bnc#951440).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers are valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-2925: The prepend_path function in fs/dcache.c
    in the Linux kernel did not properly handle rename
    actions inside a bind mount, which allowed local users
    to bypass an intended container protection mechanism by
    renaming a directory, related to a 'double-chroot attack
    (bnc#926238).

  - CVE-2015-7990: RDS: Verify the underlying transport
    exists before creating a connection, preventing possible
    DoS (bsc#952384).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=758040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=814440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=921949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=939826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=939926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=941113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=941202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=943959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=944296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=947241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=947478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=949100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=949192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=949706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=949744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=952384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=952666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0272/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2925/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5156/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7799/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7872/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7990/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8215/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152292-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9179e39b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2015-985=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2015-985=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2015-985=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-985=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-985=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2015-985=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-60.20.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-60.20.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
