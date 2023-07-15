#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:805 and 
# CentOS Errata and Security Advisory 2005:805 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21966);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2977");
  script_xref(name:"RHSA", value:"2005:805");

  script_name(english:"CentOS 4 : pam (CESA-2005:805)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated pam package that fixes a security weakness is now available
for Red Hat Enterprise Linux 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

PAM (Pluggable Authentication Modules) is a system security tool that
allows system administrators to set an authentication policy without
having to recompile programs that handle authentication.

A bug was found in the way PAM's unix_chkpwd helper program validates
user passwords when SELinux is enabled. Under normal circumstances, it
is not possible for a local non-root user to verify the password of
another local user with the unix_chkpwd command. A patch applied that
adds SELinux functionality makes it possible for a local user to use
brute-force password guessing techniques against other local user
accounts. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2977 to this issue.

All users of pam should upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c158255"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?334f03ff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b92a07dd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pam packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"pam-0.77-66.13")) flag++;
if (rpm_check(release:"CentOS-4", reference:"pam-devel-0.77-66.13")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam / pam-devel");
}
