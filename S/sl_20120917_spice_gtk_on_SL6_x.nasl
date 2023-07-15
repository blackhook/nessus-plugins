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
  script_id(62175);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4425");

  script_name(english:"Scientific Linux Security Update : spice-gtk on SL6.x i386/x86_64 (20120917)");
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
"The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
(Simple Protocol for Independent Computing Environments) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

It was discovered that the spice-gtk setuid helper application,
spice-client-glib-usb-acl-helper, did not clear the environment
variables read by the libraries it uses. A local attacker could
possibly use this flaw to escalate their privileges by setting
specific environment variables before running the helper application.
(CVE-2012-4425)

All users of spice-gtk are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.

To resolve dependencies gtk2, libcacard, libusb1, and spice-protocol
have been added to the necessary repositories."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=2915
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e703ace9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"spice-glib-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"spice-glib-devel-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-devel-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-python-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"SL6", reference:"spice-gtk-tools-0.11-11.el6_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spice-glib / spice-glib-devel / spice-gtk / spice-gtk-devel / etc");
}
