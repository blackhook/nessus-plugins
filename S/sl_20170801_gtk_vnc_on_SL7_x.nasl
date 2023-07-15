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
  script_id(102644);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-5884", "CVE-2017-5885");

  script_name(english:"Scientific Linux Security Update : gtk-vnc on SL7.x x86_64 (20170801)");
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
"The following packages have been upgraded to a later upstream version:
gtk-vnc (0.7.0).

Security Fix(es) :

  - It was found that gtk-vnc lacked proper bounds checking
    while processing messages using RRE, hextile, or
    copyrect encodings. A remote malicious VNC server could
    use this flaw to crash VNC viewers which are based on
    the gtk-vnc library. (CVE-2017-5884)

  - An integer overflow flaw was found in gtk-vnc. A remote
    malicious VNC server could use this flaw to crash VNC
    viewers which are based on the gtk-vnc library.
    (CVE-2017-5885)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1708&L=scientific-linux-errata&F=&S=&P=13678
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?609acd89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-vnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-vnc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-vnc-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-vnc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtk-vnc2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gvnc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gvnc-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gvncpulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gvncpulse-devel");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-vnc-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-vnc-debuginfo-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-vnc-devel-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-vnc-python-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-vnc2-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gtk-vnc2-devel-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gvnc-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gvnc-devel-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gvnc-tools-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gvncpulse-0.7.0-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gvncpulse-devel-0.7.0-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk-vnc / gtk-vnc-debuginfo / gtk-vnc-devel / gtk-vnc-python / etc");
}
