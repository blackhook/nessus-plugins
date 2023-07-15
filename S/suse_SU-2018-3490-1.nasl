#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3490-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118491);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-17963", "CVE-2018-3646");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2018:3490-1) (Foreshadow)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for xen fixes the following issues :

XEN was updated to the Xen 4.9.3 bug fix only release (bsc#1027519)

CVE-2018-17963: qemu_deliver_packet_iov accepted packet sizes greater
than INT_MAX, which allows attackers to cause a denial of service or
possibly have unspecified other impact. (bsc#1111014)

CVE-2018-15470: oxenstored might not have enforced the configured
quota-maxentity. This allowed a malicious or buggy guest to write as
many xenstore entries as it wishes, causing unbounded memory usage in
oxenstored. This can lead to a system-wide DoS. (XSA-272)
(bsc#1103279)

CVE-2018-15469: ARM never properly implemented grant table v2, either
in the hypervisor or in Linux. Unfortunately, an ARM guest can still
request v2 grant tables; they will simply not be properly set up,
resulting in subsequent grant-related hypercalls hitting BUG() checks.
An unprivileged guest can cause a BUG() check in the hypervisor,
resulting in a denial-of-service (crash). (XSA-268) (bsc#1103275) Note
that SUSE does not ship ARM Xen, so we are not affected.

CVE-2018-15468: The DEBUGCTL MSR contains several debugging features,
some of which virtualise cleanly, but some do not. In particular,
Branch Trace Store is not virtualised by the processor, and software
has to be careful to configure it suitably not to lock up the core. As
a result, it must only be available to fully trusted guests.
Unfortunately, in the case that vPMU is disabled, all value checking
was skipped, allowing the guest to choose any MSR_DEBUGCTL setting it
likes. A malicious or buggy guest administrator (on Intel x86 HVM or
PVH) can lock up the entire host, causing a Denial of Service.
(XSA-269) (bsc#1103276)

CVE-2018-3646: Systems with microprocessors utilizing speculative
execution and address translations may have allowed unauthorized
disclosure of information residing in the L1 data cache to an attacker
with local user access with guest OS privilege via a terminal page
fault and a side-channel analysis. (XSA-273) (bsc#1091107)

Non security issues fixed: The affinity reporting via 'xl vcpu-list'
was broken (bsc#1106263)

Kernel oops in fs/dcache.c called by d_materialise_unique()
(bsc#1094508)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15468/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15469/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17963/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3646/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183490-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6171ceda"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2492=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2492=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2492=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17963");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-debugsource-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-debugsource-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.9.3_03-3.44.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"xen-libs-debuginfo-4.9.3_03-3.44.2")) flag++;


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
