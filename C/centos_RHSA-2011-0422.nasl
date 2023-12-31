#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0422 and 
# CentOS Errata and Security Advisory 2011:0422 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53338);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2937", "CVE-2011-0411");
  script_xref(name:"RHSA", value:"2011:0422");

  script_name(english:"CentOS 4 / 5 : postfix (CESA-2011:0422)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postfix packages that fix two security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH
(SASL), and TLS.

It was discovered that Postfix did not flush the received SMTP
commands buffer after switching to TLS encryption for an SMTP session.
A man-in-the-middle attacker could use this flaw to inject SMTP
commands into a victim's session during the plain text phase. This
would lead to those commands being processed by Postfix after TLS
encryption is enabled, possibly allowing the attacker to steal the
victim's mail or authentication credentials. (CVE-2011-0411)

It was discovered that Postfix did not properly check the permissions
of users' mailbox files. A local attacker able to create files in the
mail spool directory could use this flaw to create mailbox files for
other local users, and be able to read mail delivered to those users.
(CVE-2008-2937)

Red Hat would like to thank the CERT/CC for reporting CVE-2011-0411,
and Sebastian Krahmer of the SuSE Security Team for reporting
CVE-2008-2937. The CERT/CC acknowledges Wietse Venema as the original
reporter of CVE-2011-0411.

Users of Postfix are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the postfix service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d43a8725"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017279.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79c7417f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32e257ca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec878b9d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfix packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:postfix-pflogsumm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postfix-2.2.10-1.4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postfix-2.2.10-1.4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"postfix-pflogsumm-2.2.10-1.4.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"postfix-pflogsumm-2.2.10-1.4.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"postfix-2.3.3-2.2.el5_6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"postfix-pflogsumm-2.3.3-2.2.el5_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfix / postfix-pflogsumm");
}
