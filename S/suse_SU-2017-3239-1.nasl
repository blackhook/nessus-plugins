#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3239-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105148);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-13672", "CVE-2017-15289", "CVE-2017-15592", "CVE-2017-15595", "CVE-2017-15597");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2017:3239-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues. These security issues were
fixed :

  - bsc#1068187: Failure to recognize errors in the Populate
    on Demand (PoD) code allowed for DoS (XSA-246)

  - bsc#1068191: Missing p2m error checking in PoD code
    allowed unprivileged guests to retain a writable mapping
    of freed memory leading to information leaks, privilege
    escalation or DoS (XSA-247).

  - CVE-2017-15289: The mode4and5 write functions allowed
    local OS guest privileged users to cause a denial of
    service (out-of-bounds write access and Qemu process
    crash) via vectors related to dst calculation
    (bsc#1063123)

  - CVE-2017-15597: A grant copy operation being done on a
    grant of a dying domain allowed a malicious guest
    administrator to corrupt hypervisor memory, allowing for
    DoS or potentially privilege escalation and information
    leaks (bsc#1061075).

  - CVE-2017-15595: x86 PV guest OS users were able to cause
    a DoS (unbounded recursion, stack consumption, and
    hypervisor crash) or possibly gain privileges via
    crafted page-table stacking (bsc#1061081).

  - CVE-2017-15592: x86 HVM guest OS users were able to
    cause a DoS (hypervisor crash) or possibly gain
    privileges because self-linear shadow mappings were
    mishandled for translated guests (bsc#1061086).

  - CVE-2017-13672: The VGA display emulator support allowed
    local guest OS privileged users to cause a denial of
    service (out-of-bounds read and QEMU process crash) via
    vectors involving display update (bsc#1056336)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1055047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1061086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15289/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15592/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15595/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15597/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173239-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a563698a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-2019=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_26_k3.12.61_52.101-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_26_k3.12.61_52.101-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_26-22.59.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.4_26-22.59.3")) flag++;


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
