#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0465 and 
# Oracle Linux Security Advisory ELSA-2016-0465 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90074);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-1908", "CVE-2016-3115");
  script_xref(name:"RHSA", value:"2016:0465");

  script_name(english:"Oracle Linux 7 : openssh (ELSA-2016-0465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0465 :

Updated openssh packages that fix two security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

It was discovered that the OpenSSH server did not sanitize data
received in requests to enable X11 forwarding. An authenticated client
with restricted SSH access could possibly use this flaw to bypass
intended restrictions. (CVE-2016-3115)

An access flaw was discovered in OpenSSH; the OpenSSH client did not
correctly handle failures to generate authentication cookies for
untrusted X11 forwarding. A malicious or compromised remote X
application could possibly use this flaw to establish a trusted
connection to the local X server, even if only untrusted X11
forwarding was requested. (CVE-2016-1908)

All openssh users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the OpenSSH server daemon (sshd) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005876.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-25.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.25.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-keycat / etc");
}
