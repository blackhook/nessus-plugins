#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2088 and 
# Oracle Linux Security Advisory ELSA-2015-2088 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87019);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_xref(name:"RHSA", value:"2015:2088");

  script_name(english:"Oracle Linux 7 : openssh (ELSA-2015-2088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2088 :

Updated openssh packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A flaw was found in the way OpenSSH handled PAM authentication when
using privilege separation. An attacker with valid credentials on the
system and able to fully compromise a non-privileged
pre-authentication process using a different flaw could use this flaw
to authenticate as other users. (CVE-2015-6563)

A use-after-free flaw was found in OpenSSH. An attacker able to fully
compromise a non-privileged pre-authentication process using a
different flaw could possibly cause sshd to crash or execute arbitrary
code with root privileges. (CVE-2015-6564)

It was discovered that the OpenSSH sshd daemon did not check the list
of keyboard-interactive authentication methods for duplicates. A
remote attacker could use this flaw to bypass the MaxAuthTries limit,
making it easier to perform password guessing attacks. (CVE-2015-5600)

It was found that the OpenSSH ssh-agent, a program to hold private
keys used for public key authentication, was vulnerable to password
guessing attacks. An attacker able to connect to the agent could use
this flaw to conduct a brute-force attack to unlock keys in the
ssh-agent. (BZ#1238238)

This update fixes the following bugs :

* Previously, the sshd_config(5) man page was misleading and could
thus confuse the user. This update improves the man page text to
clearly describe the AllowGroups feature. (BZ#1150007)

* The limit for the function for restricting the number of files
listed using the wildcard character (*) that prevents the Denial of
Service (DoS) for both server and client was previously set too low.
Consequently, the user reaching the limit was prevented from listing a
directory with a large number of files over Secure File Transfer
Protocol (SFTP). This update increases the aforementioned limit, thus
fixing this bug. (BZ#1160377)

* When the ForceCommand option with a pseudoterminal was used and the
MaxSession option was set to '2', multiplexed SSH connections did not
work as expected. After the user attempted to open a second
multiplexed connection, the attempt failed if the first connection was
still open. This update modifies OpenSSH to issue only one audit
message per session, and the user is thus able to open two multiplexed
connections in this situation. (BZ#1199112)

* The ssh-copy-id utility failed if the account on the remote server
did not use an sh-like shell. Remote commands have been modified to
run in an sh-like shell, and ssh-copy-id now works also with
non-sh-like shells. (BZ#1201758)

* Due to a race condition between auditing messages and answers when
using ControlMaster multiplexing, one session in the shared connection
randomly and unexpectedly exited the connection. This update fixes the
race condition in the auditing code, and multiplexing connections now
work as expected even with a number of sessions created at once.
(BZ#1240613)

In addition, this update adds the following enhancements :

* As not all Lightweight Directory Access Protocol (LDAP) servers
possess a default schema, as expected by the ssh-ldap-helper program,
this update provides the user with an ability to adjust the LDAP query
to get public keys from servers with a different schema, while the
default functionality stays untouched. (BZ#1201753)

* With this enhancement update, the administrator is able to set
permissions for files uploaded using Secure File Transfer Protocol
(SFTP). (BZ#1197989)

* This update provides the LDAP schema in LDAP Data Interchange Format
(LDIF) format as a complement to the old schema previously accepted by
OpenLDAP. (BZ#1184938)

* With this update, the user can selectively disable the Generic
Security Services API (GSSAPI) key exchange algorithms as any normal
key exchange. (BZ#1253062)

Users of openssh are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005560.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.22.el7")) flag++;


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
