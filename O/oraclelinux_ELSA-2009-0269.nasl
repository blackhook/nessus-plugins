#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0269 and 
# Oracle Linux Security Advisory ELSA-2009-0269 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67802);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0398");
  script_bugtraq_id(33405);
  script_xref(name:"RHSA", value:"2009:0269");

  script_name(english:"Oracle Linux 3 : gstreamer-plugins (ELSA-2009-0269)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0269 :

Updated gstreamer-plugins packages that fix one security issue are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gstreamer-plugins package contains plug-ins used by the GStreamer
streaming-media framework to support a wide variety of media types.

An array indexing error was found in the GStreamer's QuickTime media
file format decoding plug-in. An attacker could create a
carefully-crafted QuickTime media .mov file that would cause an
application using GStreamer to crash or, potentially, execute
arbitrary code if played by a victim. (CVE-2009-0398)

All users of gstreamer-plugins are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing the update, all applications using GStreamer (such as
nautilus-media) must be restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-February/000885.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gstreamer-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gstreamer-plugins-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/07");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gstreamer-plugins-0.6.0-19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gstreamer-plugins-0.6.0-19")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"gstreamer-plugins-devel-0.6.0-19")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"gstreamer-plugins-devel-0.6.0-19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins / gstreamer-plugins-devel");
}
