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
  script_id(71302);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1940");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL6.x i386/x86_64 (20131121)");
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
"A flaw was found in the way the X.org X11 server registered new hot
plugged devices. If a local user switched to a different session and
plugged in a new device, input from that device could become available
in the previous session, possibly leading to information disclosure.
(CVE-2013-1940)

This update also fixes the following bugs :

  - A previous upstream patch modified the Xephyr X server
    to be resizeable, however, it did not enable the resize
    functionality by default. As a consequence, X sandboxes
    were not resizeable on Scientific Linux 6.4 and later.
    This update enables the resize functionality by default
    so that X sandboxes can now be resized as expected.

  - In Scientific Linux 6, the X Security extension
    (XC-SECURITY) has been disabled and replaced by X Access
    Control Extension (XACE). However, XACE does not yet
    include functionality that was previously available in
    XC- SECURITY. With this update, XC-SECURITY is enabled
    in the xorg-x11-server spec file on Scientific Linux 6.

  - Upstream code changes to extension initialization
    accidentally disabled the GLX extension in Xvfb (the X
    virtual frame buffer), rendering headless 3D
    applications not functional. An upstream patch to this
    problem has been backported so the GLX extension is
    enabled again, and applications relying on this
    extension work as expected."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=2569
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6d96acd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-debuginfo-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.13.0-23.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.13.0-23.sl6")) flag++;


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
