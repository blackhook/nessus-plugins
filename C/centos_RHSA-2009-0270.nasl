#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0270 and 
# CentOS Errata and Security Advisory 2009:0270 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35603);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0397");
  script_bugtraq_id(33405);
  script_xref(name:"RHSA", value:"2009:0270");

  script_name(english:"CentOS 4 : gstreamer-plugins (CESA-2009:0270)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gstreamer-plugins packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gstreamer-plugins package contains plugins used by the GStreamer
streaming-media framework to support a wide variety of media types.

A heap buffer overflow was found in the GStreamer's QuickTime media
file format decoding plug-in. An attacker could create a
carefully-crafted QuickTime media .mov file that would cause an
application using GStreamer to crash or, potentially, execute
arbitrary code if played by a victim. (CVE-2009-0397)

All users of gstreamer-plugins are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing the update, all applications using GStreamer (such as
rhythmbox) must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015621.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a205b12c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69d429f9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-February/015626.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d095df7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", reference:"gstreamer-plugins-0.8.5-1.EL.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gstreamer-plugins-devel-0.8.5-1.EL.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins / gstreamer-plugins-devel");
}
