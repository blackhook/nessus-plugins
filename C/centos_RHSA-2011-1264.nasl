#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1264 and 
# CentOS Errata and Security Advisory 2011:1264 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56126);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915");
  script_bugtraq_id(48979);
  script_xref(name:"RHSA", value:"2011:1264");

  script_name(english:"CentOS 4 : gstreamer-plugins (CESA-2011:1264)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gstreamer-plugins packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The gstreamer-plugins packages contain plug-ins used by the GStreamer
streaming-media framework to support a wide variety of media formats.

An integer overflow flaw, a boundary error, and multiple off-by-one
flaws were found in various ModPlug music file format library
(libmodplug) modules, embedded in GStreamer. An attacker could create
specially crafted music files that, when played by a victim, would
cause applications using GStreamer to crash or, potentially, execute
arbitrary code. (CVE-2011-2911, CVE-2011-2912, CVE-2011-2913,
CVE-2011-2914, CVE-2011-2915)

All users of gstreamer-plugins are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing the update, all applications using GStreamer (such as
Rhythmbox) must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da8aed77"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50d39208"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gstreamer-plugins-0.8.5-1.EL.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gstreamer-plugins-0.8.5-1.EL.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gstreamer-plugins-devel-0.8.5-1.EL.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gstreamer-plugins-devel-0.8.5-1.EL.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins / gstreamer-plugins-devel");
}
