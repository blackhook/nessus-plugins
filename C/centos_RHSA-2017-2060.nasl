#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2060 and 
# CentOS Errata and Security Advisory 2017:2060 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102752);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-10198", "CVE-2016-10199", "CVE-2016-9446", "CVE-2016-9810", "CVE-2016-9811", "CVE-2017-5837", "CVE-2017-5838", "CVE-2017-5839", "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5842", "CVE-2017-5843", "CVE-2017-5844", "CVE-2017-5845", "CVE-2017-5848");
  script_xref(name:"RHSA", value:"2017:2060");

  script_name(english:"CentOS 7 : clutter-gst2 / gnome-video-effects / gstreamer-plugins-bad-free / etcgstreamer1 / etc (CESA-2017:2060)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GStreamer is a streaming media framework based on graphs of filters
which operate on media data.

The following packages have been upgraded to a later upstream version:
clutter-gst2 (2.0.18), gnome-video-effects (0.4.3), gstreamer1
(1.10.4), gstreamer1-plugins-bad-free (1.10.4),
gstreamer1-plugins-base (1.10.4), gstreamer1-plugins-good (1.10.4),
orc (0.4.26).

Security Fix(es) :

* Multiple flaws were found in gstreamer1, gstreamer1-plugins-base,
gstreamer1-plugins-good, and gstreamer1-plugins-bad-free packages. An
attacker could potentially use these flaws to crash applications which
use the GStreamer framework. (CVE-2016-9446, CVE-2016-9810,
CVE-2016-9811, CVE-2016-10198, CVE-2016-10199, CVE-2017-5837,
CVE-2017-5838, CVE-2017-5839, CVE-2017-5840, CVE-2017-5841,
CVE-2017-5842, CVE-2017-5843, CVE-2017-5844, CVE-2017-5845,
CVE-2017-5848)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf60fc6c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?548b2c59"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40bff417"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004195.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea8f519e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004196.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae48cf6e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004197.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5da3bda"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004198.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?778c2007"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca48ae06"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd9b4b9b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10199");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter-gst2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:clutter-gst2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-video-effects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-good-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-bad-free-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-base-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:orc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:orc-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:orc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:orc-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"clutter-gst2-2.0.18-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"clutter-gst2-devel-2.0.18-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-video-effects-0.4.3-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-0.10.23-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-devel-0.10.23-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-devel-docs-0.10.23-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer-plugins-good-0.10.31-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer-plugins-good-devel-docs-0.10.31-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-devel-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-devel-docs-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-bad-free-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-bad-free-devel-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-bad-free-gtk-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-1.10.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-devel-1.10.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-devel-docs-1.10.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-base-tools-1.10.4-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gstreamer1-plugins-good-1.10.4-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"orc-0.4.26-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"orc-compiler-0.4.26-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"orc-devel-0.4.26-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"orc-doc-0.4.26-1.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clutter-gst2 / clutter-gst2-devel / gnome-video-effects / etc");
}
