#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100779);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-7718", "CVE-2017-7980");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL7.x x86_64 (20170613)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - An out-of-bounds r/w access issue was found in QEMU's
    Cirrus CLGD 54xx VGA Emulator support. The vulnerability
    could occur while copying VGA data via various bitblt
    functions. A privileged user inside a guest could use
    this flaw to crash the QEMU process or, potentially,
    execute arbitrary code on the host with privileges of
    the QEMU process. (CVE-2017-7980)

  - An out-of-bounds access issue was found in QEMU's Cirrus
    CLGD 54xx VGA Emulator support. The vulnerability could
    occur while copying VGA data using bitblt functions (for
    example, cirrus_bitblt_rop_fwd_transp_). A privileged
    user inside a guest could use this flaw to crash the
    QEMU process, resulting in denial of service.
    (CVE-2017-7718)

Bug Fix(es) :

  - Previously, guest virtual machines in some cases became
    unresponsive when the 'pty' back end of a serial device
    performed an irregular I/O communication. This update
    improves the handling of serial I/O on guests, which
    prevents the described problem from occurring."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1706&L=scientific-linux-errata&F=&S=&P=1955
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdfbf3f5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-img-1.5.3-126.el7_3.9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-126.el7_3.9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-126.el7_3.9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-126.el7_3.9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-126.el7_3.9")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-common / qemu-kvm-debuginfo / etc");
}
