#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1826 and 
# CentOS Errata and Security Advisory 2014:1826 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79188);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_bugtraq_id(70091, 70092, 70093, 70094, 70096);
  script_xref(name:"RHSA", value:"2014:1826");

  script_name(english:"CentOS 6 / 7 : libvncserver (CESA-2014:1826)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvncserver packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

LibVNCServer is a library that allows for easy creation of VNC server
or client functionality.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way screen sizes were handled by LibVNCServer. A
malicious VNC server could use this flaw to cause a client to crash
or, potentially, execute arbitrary code in the client. (CVE-2014-6051)

A NULL pointer dereference flaw was found in LibVNCServer's
framebuffer setup. A malicious VNC server could use this flaw to cause
a VNC client to crash. (CVE-2014-6052)

A NULL pointer dereference flaw was found in the way LibVNCServer
handled certain ClientCutText message. A remote attacker could use
this flaw to crash the VNC server by sending a specially crafted
ClientCutText message from a VNC client. (CVE-2014-6053)

A divide-by-zero flaw was found in the way LibVNCServer handled the
scaling factor when it was set to '0'. A remote attacker could use
this flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6054)

Two stack-based buffer overflow flaws were found in the way
LibVNCServer handled file transfers. A remote attacker could use this
flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6055)

Red Hat would like to thank oCERT for reporting these issues. oCERT
acknowledges Nicolas Ruff as the original reporter.

All libvncserver users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running applications linked against libvncserver must be restarted
for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-November/020747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad9df66e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-November/020758.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7badfd9e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvncserver packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6051");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvncserver-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libvncserver-0.9.7-7.el6_6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libvncserver-devel-0.9.7-7.el6_6.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvncserver-0.9.9-9.el7_0.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvncserver-devel-0.9.9-9.el7_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvncserver / libvncserver-devel");
}
