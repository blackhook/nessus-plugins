#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0519 and 
# Oracle Linux Security Advisory ELSA-2013-0519 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68755);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5536");
  script_bugtraq_id(58097);
  script_xref(name:"RHSA", value:"2013:0519");

  script_name(english:"Oracle Linux 6 : openssh (ELSA-2013-0519)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0519 :

Updated openssh packages that fix one security issue, multiple bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenSSH is OpenBSD's Secure Shell (SSH) protocol implementation. These
packages include the core files necessary for the OpenSSH client and
server.

Due to the way the pam_ssh_agent_auth PAM module was built in Red Hat
Enterprise Linux 6, the glibc's error() function was called rather
than the intended error() function in pam_ssh_agent_auth to report
errors. As these two functions expect different arguments, it was
possible for an attacker to cause an application using
pam_ssh_agent_auth to crash, disclose portions of its memory or,
potentially, execute arbitrary code. (CVE-2012-5536)

Note that the pam_ssh_agent_auth module is not used in Red Hat
Enterprise Linux 6 by default.

This update also fixes the following bugs :

* All possible options for the new RequiredAuthentications directive
were not documented in the sshd_config man page. This update improves
the man page to document all the possible options. (BZ#821641)

* When stopping one instance of the SSH daemon (sshd), the sshd init
script (/etc/rc.d/init.d/sshd) stopped all sshd processes regardless
of the PID of the processes. This update improves the init script so
that it only kills processes with the relevant PID. As a result, the
init script now works more reliably in a multi-instance environment.
(BZ#826720)

* Due to a regression, the ssh-copy-id command returned an exit status
code of zero even if there was an error in copying the key to a remote
host. With this update, a patch has been applied and ssh-copy-id now
returns a non-zero exit code if there is an error in copying the SSH
certificate to a remote host. (BZ#836650)

* When SELinux was disabled on the system, no on-disk policy was
installed, a user account was used for a connection, and no '~/.ssh'
configuration was present in that user's home directory, the SSH
client terminated unexpectedly with a segmentation fault when
attempting to connect to another system. A patch has been provided to
address this issue and the crashes no longer occur in the described
scenario. (BZ#836655)

* The 'HOWTO' document
/usr/share/doc/openssh-ldap-5.3p1/HOWTO.ldap-keys incorrectly
documented the use of the AuthorizedKeysCommand directive. This update
corrects the document. (BZ#857760)

This update also adds the following enhancements :

* When attempting to enable SSH for use with a Common Access Card
(CAC), the ssh-agent utility read all the certificates in the card
even though only the ID certificate was needed. Consequently, if a
user entered their PIN incorrectly, then the CAC was locked, as a
match for the PIN was attempted against all three certificates. With
this update, ssh-add does not try the same PIN for every certificate
if the PIN fails for the first one. As a result, the CAC will not be
disabled if a user enters their PIN incorrectly. (BZ#782912)

* This update adds a 'netcat mode' to SSH. The 'ssh -W host:port ...'
command connects standard input and output (stdio) on a client to a
single port on a server. As a result, SSH can be used to route
connections via intermediate servers. (BZ#860809)

* Due to a bug, arguments for the RequiredAuthentications2 directive
were not stored in a Match block. Consequently, parsing of the config
file was not in accordance with the man sshd_config documentation.
This update fixes the bug and users can now use the required
authentication feature to specify a list of authentication methods as
expected according to the man page. (BZ#869903)

All users of openssh are advised to upgrade to these updated packages,
which fix these issues and add these enhancements. After installing
this update, the OpenSSH server daemon (sshd) will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-February/003286.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openssh-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-askpass-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-clients-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-ldap-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-server-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pam_ssh_agent_auth-0.9.3-84.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-ldap / etc");
}
