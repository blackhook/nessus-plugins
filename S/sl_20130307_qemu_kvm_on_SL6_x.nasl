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
  script_id(65092);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-6075");

  script_name(english:"Scientific Linux Security Update : qemu-kvm on SL6.x i386/x86_64 (20130307)");
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
"A flaw was found in the way QEMU-KVM emulated the e1000 network
interface card when the host was configured to accept jumbo network
frames, and a guest using the e1000 emulated driver was not. A remote
attacker could use this flaw to crash the guest or, potentially,
execute arbitrary code with root privileges in the guest.
(CVE-2012-6075)

After installing this update, shut down all running virtual machines.
Once all virtual machines have shut down, start them again for this
update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=3090
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?815bbbce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-guest-agent-win32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-vdagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-xpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:usbredir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:usbredir-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:usbredir-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virt-viewer");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"qemu-guest-agent-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-guest-agent-win32-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"qemu-kvm-debuginfo-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.355.el6_4.2")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"seabios-0.6.1.2-26.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-glib-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-glib-devel-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-devel-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-python-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-tools-0.14-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-protocol-0.12.2-1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-0.12.0-12.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"spice-server-devel-0.12.0-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-vdagent-0.12.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"spice-xpi-2.7-22.el6")) flag++;
if (rpm_check(release:"SL6", reference:"usbredir-0.5.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"usbredir-devel-0.5.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"usbredir-server-0.5.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"virt-viewer-0.5.2-18.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-guest-agent-win32 / qemu-img / qemu-kvm / etc");
}
