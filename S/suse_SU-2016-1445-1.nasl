#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1445-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91649);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-0222", "CVE-2014-7815", "CVE-2015-5278", "CVE-2015-8743", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2841");
  script_bugtraq_id(67357, 70998);

  script_name(english:"SUSE SLES10 Security Update : Xen (SUSE-SU-2016:1445-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to fix the following security issues :

CVE-2016-2841: net: ne2000: infinite loop in ne2000_receive
(bsc#969351)

CVE-2016-2391: usb: multiple eof_timers in ohci module leads to NULL
pointer dereference (bsc#967101)

CVE-2016-2270: x86: inconsistent cachability flags on guest mappings
(XSA-154) (bsc#965315)

CVE-2016-2271: VMX: guest user mode may crash guest with non-canonical
RIP (XSA-170) (bsc#965317)

CVE-2015-5278: Infinite loop in ne2000_receive() function (bsc#964947)

CVE-2014-0222: qcow1: validate L2 table size to avoid integer
overflows (bsc#964925)

CVE-2014-7815: vnc: insufficient bits_per_pixel from the client
sanitization (bsc#962627)

CVE-2015-8743: ne2000: OOB memory access in ioport r/w functions
(bsc#960726)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969351"
  );
  # https://download.suse.com/patch/finder/?keywords=5674a3bc2ab2548e9b2b0ec9973724d0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e36bcf06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0222/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7815/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5278/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8743/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2270/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2271/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2391/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2841/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161445-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dca3a04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Xen packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-ioemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-devel-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-html-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-pdf-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-doc-ps-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-debug-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdump-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-smp-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-tools-ioemu-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-bigsmp-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-kdumppae-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmi-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"xen-kmp-vmipae-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-devel-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-html-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-pdf-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-doc-ps-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-debug-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-default-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdump-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-smp-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-libs-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-domU-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-tools-ioemu-3.2.3_17040_46-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-bigsmp-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-kdumppae-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmi-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"xen-kmp-vmipae-3.2.3_17040_46_2.6.16.60_0.132.8-0.25.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
