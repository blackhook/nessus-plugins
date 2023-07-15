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
  script_id(97379);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2016-2857", "CVE-2017-2615");
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL6.x i386/x86_64 (20170223)");
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

  - Quick emulator (Qemu) built with the Cirrus CLGD 54xx
    VGA emulator support is vulnerable to an out-of-bounds
    access issue. It could occur while copying VGA data via
    bitblt copy in backward mode. A privileged user inside a
    guest could use this flaw to crash the Qemu process
    resulting in DoS or potentially execute arbitrary code
    on the host with privileges of Qemu process on the host.
    (CVE-2017-2615)

  - An out-of-bounds read-access flaw was found in the QEMU
    emulator built with IP checksum routines. The flaw could
    occur when computing a TCP/UDP packet's checksum,
    because a QEMU function used the packet's payload length
    without checking against the data buffer's size. A user
    inside a guest could use this flaw to crash the QEMU
    process (denial of service). (CVE-2016-2857)

This update also fixes the following bug :

  - Previously, rebooting a guest virtual machine more than
    128 times in a short period of time caused the guest to
    shut down instead of rebooting, because the virtqueue
    was not cleaned properly. This update ensures that the
    virtqueue is cleaned more reliably, which prevents the
    described problem from occurring.

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1702&L=scientific-linux-errata&F=&S=&P=5279
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c99b26da"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.491.el6_8.6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.491.el6_8.6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.491.el6_8.6")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.491.el6_8.6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.491.el6_8.6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-debuginfo / etc");
}
