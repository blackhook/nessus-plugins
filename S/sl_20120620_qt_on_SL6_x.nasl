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
  script_id(61347);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-5076", "CVE-2011-3922");

  script_name(english:"Scientific Linux Security Update : qt on SL6.x i386/x86_64 (20120620)");
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
"Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System. HarfBuzz is an OpenType text shaping engine.

A buffer overflow flaw was found in the harfbuzz module in Qt. If a
user loaded a specially crafted font file with an application linked
against Qt, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3922)

A flaw was found in the way Qt handled X.509 certificates with IP
address wildcards. An attacker able to obtain a certificate with a
Common Name containing an IP wildcard could possibly use this flaw to
impersonate an SSL server to client applications that are using Qt.
This update also introduces more strict handling for hostname wildcard
certificates by disallowing the wildcard character to match more than
one hostname component. (CVE-2010-5076)

This update also fixes the following bugs :

  - The Phonon API allowed premature freeing of the media
    object. Consequently, GStreamer could terminate
    unexpectedly as it failed to access the released media
    object. This update modifies the underlying Phonon API
    code and the problem no longer occurs.

  - Previously, Qt could output the 'Unrecognized OpenGL
    version' error and fall back to OpenGL-version-1
    compatibility mode. This happened because Qt failed to
    recognize the version of OpenGL installed on the system
    if the system was using a version of OpenGL released
    later than the Qt version in use. This update adds the
    code for recognition of OpenGL versions to Qt and if the
    OpenGL version is unknown, Qt assumes that the
    last-known version of OpenGL is available.

  - Previously Qt included a compiled-in list of trusted CA
    (Certificate Authority) certificates, that could have
    been used if Qt failed to open a system's ca-bundle.crt
    file. With this update, Qt no longer includes
    compiled-in CA certificates and only uses the system
    bundle.

Users of Qt should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
linked against Qt libraries must be restarted for this update to take
effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=2554
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c2f9d6e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:phonon-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-x11");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/07");
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
if (rpm_check(release:"SL6", reference:"phonon-backend-gstreamer-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-debuginfo-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-demos-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-devel-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-doc-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-examples-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-mysql-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-odbc-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-postgresql-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-sqlite-4.6.2-24.el6")) flag++;
if (rpm_check(release:"SL6", reference:"qt-x11-4.6.2-24.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phonon-backend-gstreamer / qt / qt-debuginfo / qt-demos / qt-devel / etc");
}
