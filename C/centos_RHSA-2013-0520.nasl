#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0520 and 
# CentOS Errata and Security Advisory 2013:0520 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65151);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2166", "CVE-2011-2167", "CVE-2011-4318");
  script_bugtraq_id(48003, 50709);
  script_xref(name:"RHSA", value:"2013:0520");

  script_name(english:"CentOS 6 : dovecot (CESA-2013:0520)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dovecot packages that fix three security issues and one bug
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Dovecot is an IMAP server, written with security primarily in mind,
for Linux and other UNIX-like systems. It also contains a small POP3
server. It supports mail in either of maildir or mbox formats. The SQL
drivers and authentication plug-ins are provided as sub-packages.

Two flaws were found in the way some settings were enforced by the
script-login functionality of Dovecot. A remote, authenticated user
could use these flaws to bypass intended access restrictions or
conduct a directory traversal attack by leveraging login scripts.
(CVE-2011-2166, CVE-2011-2167)

A flaw was found in the way Dovecot performed remote server identity
verification, when it was configured to proxy IMAP and POP3
connections to remote hosts using TLS/SSL protocols. A remote attacker
could use this flaw to conduct man-in-the-middle attacks using an
X.509 certificate issued by a trusted Certificate Authority (for a
different name). (CVE-2011-4318)

This update also fixes the following bug :

* When a new user first accessed their IMAP inbox, Dovecot was, under
some circumstances, unable to change the group ownership of the inbox
directory in the user's Maildir location to match that of the user's
mail spool (/var/mail/$USER). This correctly generated an 'Internal
error occurred' message. However, with a subsequent attempt to access
the inbox, Dovecot saw that the directory already existed and
proceeded with its operation, leaving the directory with incorrectly
set permissions. This update corrects the underlying permissions
setting error. When a new user now accesses their inbox for the first
time, and it is not possible to set group ownership, Dovecot removes
the created directory and generates an error message instead of
keeping the directory with incorrect group ownership. (BZ#697620)

Users of dovecot are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, the dovecot service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019318.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b87d530f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c0bd76f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2166");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"dovecot-2.0.9-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-devel-2.0.9-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-mysql-2.0.9-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-pgsql-2.0.9-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dovecot-pigeonhole-2.0.9-5.el6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-devel / dovecot-mysql / dovecot-pgsql / etc");
}
