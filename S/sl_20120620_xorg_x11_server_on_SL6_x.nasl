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
  script_id(61351);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4028", "CVE-2011-4029");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL6.x i386/x86_64 (20120620)");
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
"X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A flaw was found in the way the X.Org server handled lock files. A
local user with access to the system console could use this flaw to
determine the existence of a file in a directory not accessible to the
user, via a symbolic link attack. (CVE-2011-4028)

A race condition was found in the way the X.Org server managed
temporary lock files. A local attacker could use this flaw to perform
a symbolic link attack, allowing them to make an arbitrary file world
readable, leading to the disclosure of sensitive information.
(CVE-2011-4029)

This update also fixes the following bugs :

  - Prior to this update, the KDE Display Manager (KDM)
    could pass invalid 24bpp pixmap formats to the X server.
    As a consequence, the X server could unexpectedly abort.
    This update modifies the underlying code to pass the
    correct formats.

  - Prior to this update, absolute input devices, like the
    stylus of a graphic tablet, could become unresponsive in
    the right-most or bottom-most screen if the X server was
    configured as a multi-screen setup through multiple
    'Device' sections in the xorg.conf file. This update
    changes the screen crossing behavior so that absolute
    devices are always mapped across all screens.

  - Prior to this update, the misleading message 'Session
    active, not inhibited, screen idle. If you see this
    test, your display server is broken and you should
    notify your distributor.' could be displayed after
    resuming the system or re-enabling the display, and
    included a URL to an external web page. This update
    removes this message.

  - Prior to this update, the erroneous input handling code
    of the Xephyr server disabled screens on a screen
    crossing event. The focus was only on the screen where
    the mouse was located and only this screen was updated
    when the Xephyr nested X server was configured in a
    multi-screen setup. This update removes this code and
    Xephyr now correctly updates screens in multi-screen
    setups.

  - Prior to this update, raw events did not contain
    relative axis values. As a consequence, clients which
    relied on relative values for functioning did not behave
    as expected. This update sets the values to the original
    driver values instead of the already transformed values.
    Now, raw events contain relative axis values as
    expected.

All users of xorg-x11-server are advised to upgrade to these updated
packages, which correct these issues. All running X.Org server
instances must be restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=1915
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8997fc7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-debuginfo-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.10.6-1.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.10.6-1.sl6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
