#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0859. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55013);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0411", "CVE-2011-1926");
  script_bugtraq_id(46767);
  script_xref(name:"RHSA", value:"2011:0859");

  script_name(english:"RHEL 4 / 5 / 6 : cyrus-imapd (RHSA-2011:0859)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cyrus-imapd packages that fix one security issue are now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and Sieve support.

It was discovered that cyrus-imapd did not flush the received commands
buffer after switching to TLS encryption for IMAP, LMTP, NNTP, and
POP3 sessions. A man-in-the-middle attacker could use this flaw to
inject protocol commands into a victim's TLS session initialization
messages. This could lead to those commands being processed by
cyrus-imapd, potentially allowing the attacker to steal the victim's
mail or authentication credentials. (CVE-2011-1926)

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, cyrus-imapd will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:0859"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-nntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cyrus-imapd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Cyrus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0859";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-2.2.12-15.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-devel-2.2.12-15.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-murder-2.2.12-15.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-nntp-2.2.12-15.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"cyrus-imapd-utils-2.2.12-15.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"perl-Cyrus-2.2.12-15.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cyrus-imapd-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cyrus-imapd-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cyrus-imapd-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"cyrus-imapd-devel-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cyrus-imapd-perl-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cyrus-imapd-perl-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cyrus-imapd-perl-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"cyrus-imapd-utils-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"cyrus-imapd-utils-2.3.7-7.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"cyrus-imapd-utils-2.3.7-7.el5_6.4")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cyrus-imapd-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cyrus-imapd-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cyrus-imapd-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"cyrus-imapd-debuginfo-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"cyrus-imapd-devel-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cyrus-imapd-utils-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cyrus-imapd-utils-2.3.16-6.el6_1.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cyrus-imapd-utils-2.3.16-6.el6_1.2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd / cyrus-imapd-debuginfo / cyrus-imapd-devel / etc");
  }
}
