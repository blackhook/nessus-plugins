#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0074. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24696);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-0451");
  script_bugtraq_id(22584);
  script_xref(name:"RHSA", value:"2007:0074");

  script_name(english:"RHEL 4 : spamassassin (RHSA-2007:0074)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spamassassin packages that fix a security issue are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SpamAssassin provides a way to reduce unsolicited commercial email
(spam) from incoming email.

A flaw was found in the way SpamAssassin processes HTML email
containing URIs. A carefully crafted mail message could cause
SpamAssassin to consume significant resources. If a number of these
messages are sent, this could lead to a denial of service, potentially
delaying or preventing the delivery of email. (CVE-2007-0451)

Users of SpamAssassin should upgrade to these updated packages which
contain version 3.1.8 which is not vulnerable to these issues.

This is an upgrade from SpamAssassin version 3.0.6 to 3.1.8, which
contains many bug fixes and spam detection enhancements. Further
details are available in the SpamAssassin 3.1 changelog and upgrade
guide."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/repos/asf/spamassassin/branches/3.1/UPGRADE"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/repos/asf/spamassassin/branches/3.1/Changes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:0074"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spamassassin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0074";
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
  if (rpm_check(release:"RHEL4", reference:"spamassassin-3.1.8-2.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spamassassin");
  }
}
