#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2974 and 
# CentOS Errata and Security Advisory 2016:2974 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96049);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-9445", "CVE-2016-9447");
  script_xref(name:"RHSA", value:"2016:2974");

  script_name(english:"CentOS 6 : gstreamer-plugins-bad-free (CESA-2016:2974)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gstreamer-plugins-bad-free is now available for Red Hat
Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GStreamer is a streaming media framework based on graphs of filters
which operate on media data. The gstreamer-plugins-bad-free package
contains a collection of plug-ins for GStreamer.

Security Fix(es) :

* An integer overflow flaw, leading to a heap-based buffer overflow,
was found in GStreamer's VMware VMnc video file format decoding
plug-in. A remote attacker could use this flaw to cause an application
using GStreamer to crash or, potentially, execute arbitrary code with
the privileges of the user running the application. (CVE-2016-9445)

* A memory corruption flaw was found in GStreamer's Nintendo NSF music
file format decoding plug-in. A remote attacker could use this flaw to
cause an application using GStreamer to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2016-9447)

Note: This updates removes the vulnerable Nintendo NSF plug-in."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-December/022189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?394c0775"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gstreamer-plugins-bad-free packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9447");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gstreamer-plugins-bad-free-extras");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"gstreamer-plugins-bad-free-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gstreamer-plugins-bad-free-devel-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gstreamer-plugins-bad-free-devel-docs-0.10.19-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gstreamer-plugins-bad-free-extras-0.10.19-5.el6_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-bad-free / gstreamer-plugins-bad-free-devel / etc");
}
