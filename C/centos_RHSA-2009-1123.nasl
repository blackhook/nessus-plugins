#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1123 and 
# CentOS Errata and Security Advisory 2009:1123 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43761);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1932");
  script_xref(name:"RHSA", value:"2009:1123");

  script_name(english:"CentOS 5 : gstreamer-plugins-good (CESA-2009:1123)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gstreamer-plugins-good packages that fix multiple security
issues are now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GStreamer is a streaming media framework, based on graphs of filters
which operate on media data. GStreamer Good Plug-ins is a collection
of well-supported, good quality GStreamer plug-ins.

Multiple integer overflow flaws, that could lead to a buffer overflow,
were found in the GStreamer Good Plug-ins PNG decoding handler. An
attacker could create a specially crafted PNG file that would cause an
application using the GStreamer Good Plug-ins library to crash or,
potentially, execute arbitrary code as the user running the
application when parsed. (CVE-2009-1932)

All users of gstreamer-plugins-good are advised to upgrade to these
updated packages, which contain a backported patch to correct these
issues. After installing the update, all applications using GStreamer
Good Plug-ins (such as some media playing applications) must be
restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/016005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9aaacfb9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/016006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?089dbb72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins-good packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-good-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"gstreamer-plugins-good-0.10.9-1.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gstreamer-plugins-good-devel-0.10.9-1.el5_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-good / gstreamer-plugins-good-devel");
}
