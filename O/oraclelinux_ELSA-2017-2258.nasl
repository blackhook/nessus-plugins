#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2258 and 
# Oracle Linux Security Advisory ELSA-2017-2258 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102301);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-5884", "CVE-2017-5885");
  script_xref(name:"RHSA", value:"2017:2258");

  script_name(english:"Oracle Linux 7 : gtk-vnc (ELSA-2017-2258)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2258 :

An update for gtk-vnc is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The gtk-vnc packages provide a VNC viewer widget for GTK. The gtk-vnc
widget is built by using co-routines, which allows the widget to be
completely asynchronous while remaining single-threaded.

The following packages have been upgraded to a later upstream version:
gtk-vnc (0.7.0). (BZ#1416783)

Security Fix(es) :

* It was found that gtk-vnc lacked proper bounds checking while
processing messages using RRE, hextile, or copyrect encodings. A
remote malicious VNC server could use this flaw to crash VNC viewers
which are based on the gtk-vnc library. (CVE-2017-5884)

* An integer overflow flaw was found in gtk-vnc. A remote malicious
VNC server could use this flaw to crash VNC viewers which are based on
the gtk-vnc library. (CVE-2017-5885)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007092.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gtk-vnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-vnc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-vnc-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-vnc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gtk-vnc2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvnc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvnc-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvncpulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvncpulse-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gtk-vnc-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gtk-vnc-devel-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gtk-vnc-python-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gtk-vnc2-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gtk-vnc2-devel-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gvnc-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gvnc-devel-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gvnc-tools-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gvncpulse-0.7.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gvncpulse-devel-0.7.0-2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk-vnc / gtk-vnc-devel / gtk-vnc-python / gtk-vnc2 / etc");
}
