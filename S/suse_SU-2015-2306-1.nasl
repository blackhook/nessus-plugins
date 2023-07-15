#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2306-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87528);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-5307", "CVE-2015-7504", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8345");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2015:2306-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issues :

  - bsc#956832 - CVE-2015-8345: xen: qemu: net: eepro100:
    infinite loop in processing command block list

  - bsc#956408 - CVE-2015-8339, CVE-2015-8340: xen:
    XENMEM_exchange error handling issues (XSA-159)
    xsa159.patch

  - bsc#956411 - CVE-2015-7504: xen: heap buffer overflow
    vulnerability in pcnet emulator (XSA-162)

  - bsc#954405 - CVE-2015-8104: Xen: guest to host DoS by
    triggering an infinite loop in microcode via #DB
    exception

  - bsc#953527 - CVE-2015-5307: kernel: kvm/xen: x86: avoid
    guest->host DOS by intercepting #AC (XSA-156)

  - bsc#950704 - CVE-2015-7970: xen: x86: Long latency
    populate-on-demand operation is not preemptible
    (XSA-150)

  - bsc#951845 - CVE-2015-7972: xen: x86: populate-on-demand
    balloon size inaccuracy can crash guests (XSA-153)

  - bsc#950703 - CVE-2015-7969: xen: leak of main per-domain
    vcpu pointer array (DoS) (XSA-149)

  - bsc#950705 - CVE-2015-7969: xen: x86: leak of per-domain
    profiling-related vcpu pointer array (DoS) (XSA-151)

  - bsc#950706 - CVE-2015-7971: xen: x86: some pmu and
    profiling hypercalls log without rate limiting (XSA-152)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=950706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=951845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=953527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5307/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7504/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7969/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7970/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7971/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7972/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8104/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8339/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8345/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152306-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c496f6f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-xen-20151201-12273=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-xen-20151201-12273=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-devel-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.37-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.37-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-html-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.37-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-devel-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.37-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.37-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-libs-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-tools-domU-4.1.6_08-23.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.37-23.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
