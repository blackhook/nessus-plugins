#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0136 and 
# CentOS Errata and Security Advisory 2012:0136 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57962);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0444");
  script_bugtraq_id(51753);
  script_xref(name:"RHSA", value:"2012:0136");

  script_name(english:"CentOS 4 / 5 / 6 : libvorbis (CESA-2012:0136)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvorbis packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libvorbis packages contain runtime libraries for use in programs
that support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

A heap-based buffer overflow flaw was found in the way the libvorbis
library parsed Ogg Vorbis media files. If a specially crafted Ogg
Vorbis media file was opened by an application using libvorbis, it
could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2012-0444)

Users of libvorbis should upgrade to these updated packages, which
contain a backported patch to correct this issue. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-February/018434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e64eee4b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-February/018435.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afab6c58"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-February/018436.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e121e212"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0444");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-devel-1.1.0-4.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-devel-1.1.0-4.el4.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libvorbis-1.1.2-3.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvorbis-devel-1.1.2-3.el5_7.6")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libvorbis-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvorbis-devel-1.2.3-4.el6_2.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvorbis-devel-docs-1.2.3-4.el6_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvorbis / libvorbis-devel / libvorbis-devel-docs");
}
