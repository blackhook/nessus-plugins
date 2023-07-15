#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:771 and 
# CentOS Errata and Security Advisory 2005:771 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21857);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-1487", "CVE-2004-1488", "CVE-2004-2014");
  script_bugtraq_id(11871);
  script_xref(name:"RHSA", value:"2005:771");

  script_name(english:"CentOS 3 / 4 : wget (CESA-2005:771)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated wget package that fixes several security issues is now
available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

GNU Wget is a file retrieval utility that can use either the HTTP or
FTP protocols.

A bug was found in the way wget writes files to the local disk. If a
malicious local user has write access to the directory wget is saving
a file into, it is possible to overwrite files that the user running
wget has write access to. (CVE-2004-2014)

A bug was found in the way wget filters redirection URLs. It is
possible for a malicious Web server to overwrite files the user
running wget has write access to. Note: in order for this attack to
succeed the local DNS would need to resolve '..' to an IP address,
which is an unlikely situation. (CVE-2004-1487)

A bug was found in the way wget displays HTTP response codes. It is
possible that a malicious web server could inject a specially crafted
terminal escape sequence capable of misleading the user running wget.
(CVE-2004-1488)

Users should upgrade to this updated package, which contains a version
of wget that is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3403b4c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012200.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e946d9c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012201.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ebbebc0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012203.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d04bb8b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?696339ad"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012210.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b89d5424"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wget package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"wget-1.10.1-1.30E.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"wget-1.10.1-2.4E.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wget");
}
