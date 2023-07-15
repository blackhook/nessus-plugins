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
  script_id(102658);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-10207", "CVE-2017-5581", "CVE-2017-7392", "CVE-2017-7393", "CVE-2017-7394", "CVE-2017-7395", "CVE-2017-7396");

  script_name(english:"Scientific Linux Security Update : tigervnc and fltk on SL7.x x86_64 (20170801)");
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
"FLTK (pronounced 'fulltick') is a cross-platform C++ GUI toolkit. It
provides modern GUI functionality without the bloat, and supports 3D
graphics via OpenGL and its built-in GLUT emulation.

The following packages have been upgraded to a later upstream version:
tigervnc (1.8.0), fltk (1.3.4).

Security Fix(es) :

  - A denial of service flaw was found in the TigerVNC's
    Xvnc server. A remote unauthenticated attacker could use
    this flaw to make Xvnc crash by terminating the TLS
    handshake process early. (CVE-2016-10207)

  - A double free flaw was found in the way TigerVNC handled
    ClientFence messages. A remote, authenticated attacker
    could use this flaw to make Xvnc crash by sending
    specially crafted ClientFence messages, resulting in
    denial of service. (CVE-2017-7393)

  - A missing input sanitization flaw was found in the way
    TigerVNC handled credentials. A remote unauthenticated
    attacker could use this flaw to make Xvnc crash by
    sending specially crafted usernames, resulting in denial
    of service. (CVE-2017-7394)

  - An integer overflow flaw was found in the way TigerVNC
    handled ClientCutText messages. A remote, authenticated
    attacker could use this flaw to make Xvnc crash by
    sending specially crafted ClientCutText messages,
    resulting in denial of service. (CVE-2017-7395)

  - A buffer overflow flaw, leading to memory corruption,
    was found in TigerVNC viewer. A remote malicious VNC
    server could use this flaw to crash the client vncviewer
    process resulting in denial of service. (CVE-2017-5581)

  - A memory leak flaw was found in the way TigerVNC handled
    termination of VeNCrypt connections. A remote
    unauthenticated attacker could repeatedly send
    connection requests to the Xvnc server, causing it to
    consume large amounts of memory resources over time, and
    ultimately leading to a denial of service due to memory
    exhaustion. (CVE-2017-7392)

  - A memory leak flaw was found in the way TigerVNC handled
    client connections. A remote unauthenticated attacker
    could repeatedly send connection requests to the Xvnc
    server, causing it to consume large amounts of memory
    resources over time, and ultimately leading to a denial
    of service due to memory exhaustion. (CVE-2017-7396)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=17357
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e965fdd0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fltk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fltk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fltk-fluid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fltk-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/22");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fltk-1.3.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fltk-debuginfo-1.3.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fltk-devel-1.3.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fltk-fluid-1.3.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fltk-static-1.3.4-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-debuginfo-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-icons-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-license-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tigervnc-server-applet-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-minimal-1.8.0-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tigervnc-server-module-1.8.0-1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fltk / fltk-debuginfo / fltk-devel / fltk-fluid / fltk-static / etc");
}
