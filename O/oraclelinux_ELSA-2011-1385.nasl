#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1385 and 
# Oracle Linux Security Advisory ELSA-2011-1385 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68374);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3365");
  script_bugtraq_id(49925);
  script_xref(name:"RHSA", value:"2011:1385");

  script_name(english:"Oracle Linux 4 / 5 / 6 : kdelibs / kdelibs3 (ELSA-2011-1385)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1385 :

Updated kdelibs packages for Red Hat Enterprise Linux 4 and 5 and
updated kdelibs3 packages for Red Hat Enterprise Linux 6 that fix one
security issue are now available.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The kdelibs and kdelibs3 packages provide libraries for the K Desktop
Environment (KDE).

An input sanitization flaw was found in the KSSL (KDE SSL Wrapper)
API. An attacker could supply a specially crafted SSL certificate (for
example, via a web page) to an application using KSSL, such as the
Konqueror web browser, causing misleading information to be presented
to the user, possibly tricking them into accepting the certificate as
valid. (CVE-2011-3365)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The desktop must be restarted
(log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002413.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002416.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs and / or kdelibs3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs3-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"kdelibs-3.3.1-18.0.1.el4")) flag++;
if (rpm_check(release:"EL4", reference:"kdelibs-devel-3.3.1-18.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"kdelibs-3.5.4-26.0.1.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"kdelibs-apidocs-3.5.4-26.0.1.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"kdelibs-devel-3.5.4-26.0.1.el5_7.1")) flag++;

if (rpm_check(release:"EL6", reference:"kdelibs3-3.5.10-24.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"kdelibs3-apidocs-3.5.10-24.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"kdelibs3-devel-3.5.10-24.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-apidocs / kdelibs-devel / kdelibs3 / etc");
}
