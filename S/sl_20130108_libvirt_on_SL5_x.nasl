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
  script_id(63598);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2693");

  script_name(english:"Scientific Linux Security Update : libvirt on SL5.x i386/x86_64 (20130108)");
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
"Bus and device IDs were ignored when attempting to attach multiple USB
devices with identical vendor or product IDs to a guest. This could
result in the wrong device being attached to a guest, giving that
guest root access to the device. (CVE-2012-2693)

This update also fixes the following bugs :

  - Previously, the libvirtd library failed to set the
    autostart flags for already defined QEMU domains. This
    bug has been fixed, and the domains can now be
    successfully marked as autostarted.

  - Prior to this update, the virFileAbsPath() function was
    not taking into account the slash ('/') directory
    separator when allocating memory for combining the cwd()
    function and a path. This behavior could lead to a
    memory corruption. With this update, a transformation to
    the virAsprintff() function has been introduced into
    virFileAbsPath(). As a result, the aforementioned
    behavior no longer occurs.

  - With this update, a man page of the virsh user interface
    has been enhanced with information on the
    'domxml-from-native' and 'domxml-to-native' commands. A
    correct notation of the format argument has been
    clarified. As a result, confusion is avoided when
    setting the format argument in the described commands.

After installing the updated packages, libvirtd will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=2079
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fea286d8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"libvirt-0.8.2-29.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-debuginfo-0.8.2-29.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-devel-0.8.2-29.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-python-0.8.2-29.el5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-debuginfo / libvirt-devel / libvirt-python");
}
