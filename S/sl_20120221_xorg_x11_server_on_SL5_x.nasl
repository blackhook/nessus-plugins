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
  script_id(61274);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4028");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL5.x i386/x86_64 (20120221)");
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

This update also fixes the following bugs :

  - In rare cases, if the front and back buffer of the
    miDbePositionWindow() function were not both allocated
    in video memory, or were both allocated in system
    memory, the X Window System sometimes terminated
    unexpectedly. A patch has been provided to address this
    issue and X no longer crashes in the described scenario.

  - Previously, when the miSetShape() function called the
    miRegionDestroy() function with a NULL region, X
    terminated unexpectedly if the backing store was
    enabled. Now, X no longer crashes in the described
    scenario.

  - On certain workstations running in 32-bit mode, the X11
    mouse cursor occasionally became stuck near the left
    edge of the X11 screen. A patch has been provided to
    address this issue and the mouse cursor no longer
    becomes stuck in the described scenario.

  - On certain workstations with a dual-head graphics
    adapter using the r500 driver in Zaphod mode, the mouse
    pointer was confined to one monitor screen and could not
    move to the other screen. A patch has been provided to
    address this issue and the mouse cursor works properly
    across both screens.

  - Due to a double free operation, Xvfb (X virtual
    framebuffer) terminated unexpectedly with a segmentation
    fault randomly when the last client disconnected, that
    is when the server reset. This bug has been fixed in the
    miDCCloseScreen() function and Xvfb no longer crashes.

  - Starting the Xephyr server on an AMD64 or Intel 64
    architecture with an integrated graphics adapter caused
    the server to terminate unexpectedly. This bug has been
    fixed in the code and Xephyr no longer crashes in the
    described scenario.

  - Previously, when a client made a request bigger than
    1/4th of the limit advertised in the BigRequestsEnable
    reply, the X server closed the connection unexpectedly.
    With this update, the maxBigRequestSize variable has
    been added to the code to check the size of client
    requests, thus fixing this bug.

  - When an X client running on a big-endian system called
    the XineramaQueryScreens() function, the X server
    terminated unexpectedly. This bug has been fixed in the
    xf86Xinerama module and the X server no longer crashes
    in the described scenario.

  - When installing Scientific Linux 5 on an IBM eServer
    System p blade server, the installer did not set the
    correct mode on the built-in KVM (Keyboard-Video-Mouse).
    Consequently, the graphical installer took a very long
    time to appear and then was displayed incorrectly. A
    patch has been provided to address this issue and the
    graphical installer now works as expected in the
    described scenario. Note that this fix requires the
    Scientific Linux 5.8 kernel update.

  - Lines longer than 46,340 pixels can be drawn with one of
    the coordinates being negative. However, for dashed
    lines, the miPolyBuildPoly() function overflowed the
    'int' type when setting up edges for a section of a
    dashed line. Consequently, dashed segments were not
    drawn at all. An upstream patch has been applied to
    address this issue and dashed lines are now drawn
    correctly.

All users of xorg-x11-server are advised to upgrade to these updated
packages, which correct these issues. All running X.Org server
instances must be restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2653
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eceff98c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvnc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xdmx-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xephyr-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xnest-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xorg-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvfb-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-debuginfo-1.1.1-48.90.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xorg-x11-server-sdk-1.1.1-48.90.el5")) flag++;


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
