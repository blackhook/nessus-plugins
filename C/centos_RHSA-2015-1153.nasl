#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1153 and 
# CentOS Errata and Security Advisory 2015:1153 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84347);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-2775");
  script_bugtraq_id(73922);
  script_xref(name:"RHSA", value:"2015:1153");

  script_name(english:"CentOS 7 : mailman (CESA-2015:1153)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mailman packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Mailman is a program used to help manage email discussion lists.

It was found that mailman did not sanitize the list name before
passing it to certain MTAs. A local attacker could use this flaw to
execute arbitrary code as the user running mailman. (CVE-2015-2775)

This update also fixes the following bugs :

* Previously, it was impossible to configure Mailman in a way that
Domain-based Message Authentication, Reporting & Conformance (DMARC)
would recognize Sender alignment for Domain Key Identified Mail (DKIM)
signatures. Consequently, Mailman list subscribers that belonged to a
mail server with a 'reject' policy for DMARC, such as yahoo.com or
AOL.com, were unable to receive Mailman forwarded messages from
senders residing in any domain that provided DKIM signatures. With
this update, domains with a 'reject' DMARC policy are recognized
correctly, and Mailman list administrators are able to configure the
way these messages are handled. As a result, after a proper
configuration, subscribers now correctly receive Mailman forwarded
messages in this scenario. (BZ#1229288)

* Previously, the /etc/mailman file had incorrectly set permissions,
which in some cases caused removing Mailman lists to fail with a
''NoneType' object has no attribute 'close'' message. With this
update, the permissions value for /etc/mailman is correctly set to
2775 instead of 0755, and removing Mailman lists now works as
expected. (BZ#1229307)

* Prior to this update, the mailman utility incorrectly installed the
tmpfiles configuration in the /etc/tmpfiles.d/ directory. As a
consequence, changes made to mailman tmpfiles configuration were
overwritten if the mailman packages were reinstalled or updated. The
mailman utility now installs the tmpfiles configuration in the
/usr/lib/tmpfiles.d/ directory, and changes made to them by the user
are preserved on reinstall or update. (BZ#1229306)

All mailman users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-June/021204.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e50bce75"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2775");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mailman-2.1.15-21.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman");
}
