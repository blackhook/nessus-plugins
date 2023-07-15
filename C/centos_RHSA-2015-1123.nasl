#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1123 and 
# CentOS Errata and Security Advisory 2015:1123 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84276);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159");
  script_bugtraq_id(72594, 75098, 75106);
  script_xref(name:"RHSA", value:"2015:1123");

  script_name(english:"CentOS 6 / 7 : cups (CESA-2015:1123)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

CUPS provides a portable printing layer for Linux, UNIX, and similar
operating systems.

A string reference count bug was found in cupsd, causing premature
freeing of string objects. An attacker can submit a malicious print
job that exploits this flaw to dismantle ACLs protecting privileged
operations, allowing a replacement configuration file to be uploaded
which in turn allows the attacker to run arbitrary code in the CUPS
server (CVE-2015-1158)

A cross-site scripting flaw was found in the cups web templating
engine. An attacker could use this flaw to bypass the default
configuration settings that bind the CUPS scheduler to the 'localhost'
or loopback interface. (CVE-2015-1159)

An integer overflow leading to a heap-based buffer overflow was found
in the way cups handled compressed raster image files. An attacker
could create a specially crafted image file, which when passed via the
cups Raster filter, could cause the cups filter to crash.
(CVE-2014-9679)

Red Hat would like to thank the CERT/CC for reporting CVE-2015-1158
and CVE-2015-1159 issues.

All cups users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-June/021178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?124ba55b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-June/021179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?646be46a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1158");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-ipptool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"cups-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-devel-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-libs-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-lpd-1.4.2-67.el6_6.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-php-1.4.2-67.el6_6.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-client-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-devel-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-filesystem-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-ipptool-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-libs-1.6.3-17.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"cups-lpd-1.6.3-17.el7_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-devel / cups-filesystem / cups-ipptool / etc");
}
