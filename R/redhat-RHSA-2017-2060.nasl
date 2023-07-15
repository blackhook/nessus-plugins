#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2060. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102150);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2016-10198", "CVE-2016-10199", "CVE-2016-9446", "CVE-2016-9810", "CVE-2016-9811", "CVE-2017-5837", "CVE-2017-5838", "CVE-2017-5839", "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5842", "CVE-2017-5843", "CVE-2017-5844", "CVE-2017-5845", "CVE-2017-5848");
  script_xref(name:"RHSA", value:"2017:2060");

  script_name(english:"RHEL 7 : GStreamer (RHSA-2017:2060)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-10199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5848"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-gst2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-gst2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:clutter-gst2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-video-effects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-bad-free-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-bad-free-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer-plugins-good-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-bad-free-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-bad-free-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-base-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-base-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:orc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:orc-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:orc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:orc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:orc-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2060";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"clutter-gst2-2.0.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"clutter-gst2-debuginfo-2.0.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"clutter-gst2-devel-2.0.18-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gnome-video-effects-0.4.3-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer-plugins-bad-free-0.10.23-23.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer-plugins-bad-free-debuginfo-0.10.23-23.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer-plugins-bad-free-devel-0.10.23-23.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gstreamer-plugins-bad-free-devel-docs-0.10.23-23.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gstreamer-plugins-bad-free-devel-docs-0.10.23-23.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer-plugins-good-0.10.31-13.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer-plugins-good-debuginfo-0.10.31-13.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer-plugins-good-devel-docs-0.10.31-13.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-debuginfo-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-devel-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-devel-docs-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-bad-free-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-bad-free-debuginfo-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-bad-free-devel-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-bad-free-gtk-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-base-1.10.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-base-debuginfo-1.10.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-base-devel-1.10.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-base-devel-docs-1.10.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"gstreamer1-plugins-base-tools-1.10.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"gstreamer1-plugins-base-tools-1.10.4-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-good-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-good-debuginfo-1.10.4-2.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"orc-0.4.26-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"orc-compiler-0.4.26-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"orc-compiler-0.4.26-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"orc-debuginfo-0.4.26-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"orc-devel-0.4.26-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"orc-doc-0.4.26-1.el7")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clutter-gst2 / clutter-gst2-debuginfo / clutter-gst2-devel / etc");
  }
}
