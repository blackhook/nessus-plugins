#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1417. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84944);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2002-0389", "CVE-2015-2775");
  script_bugtraq_id(4538, 73922);
  script_xref(name:"RHSA", value:"2015:1417");

  script_name(english:"RHEL 6 : mailman (RHSA-2015:1417)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated mailman packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mailman is a program used to help manage e-mail discussion lists.

It was found that mailman did not sanitize the list name before
passing it to certain MTAs. A local attacker could use this flaw to
execute arbitrary code as the user running mailman. (CVE-2015-2775)

It was found that mailman stored private email messages in a
world-readable directory. A local user could use this flaw to read
private mailing list archives. (CVE-2002-0389)

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
messages in this scenario. (BZ#1095359)

* Mailman used a console encoding when generating a subject for a
'welcome email' when new mailing lists were created by the 'newlist'
command. Consequently, when the console encoding did not match the
encoding used by Mailman for that particular language, characters in
the 'welcome email' could be displayed incorrectly. Mailman has been
fixed to use the correct encoding, and characters in the 'welcome
email' are now displayed properly. (BZ#1056366)

* The 'rmlist' command used a hard-coded path to list data based on
the VAR_PREFIX configuration variable. As a consequence, when the list
was created outside of VAR_PREFIX, it was impossible to remove it
using the 'rmlist' command. With this update, the 'rmlist' command
uses the correct LIST_DATA_DIR value instead of VAR_PREFIX, and it is
now possible to remove the list in described situation. (BZ#1008139)

* Due to an incompatibility between Python and Mailman in Red Hat
Enterprise Linux 6, when moderators were approving a moderated message
to a mailing list and checked the 'Preserve messages for the site
administrator' checkbox, Mailman failed to approve the message and
returned an error. This incompatibility has been fixed, and Mailman
now approves messages as expected in this scenario. (BZ#765807)

* When Mailman was set to not archive a list but the archive was not
set to private, attachments sent to that list were placed in a public
archive. Consequently, users of Mailman web interface could list
private attachments because httpd configuration of public archive
directory allows listing all files in the archive directory. The httpd
configuration of Mailman has been fixed to not allow listing of
private archive directory, and users of Mailman web interface are no
longer able to list private attachments. (BZ#745409)

Users of mailman are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-2775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2002-0389"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mailman and / or mailman-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1417";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mailman-2.1.12-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mailman-2.1.12-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mailman-2.1.12-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mailman-debuginfo-2.1.12-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mailman-debuginfo-2.1.12-25.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mailman-debuginfo-2.1.12-25.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman / mailman-debuginfo");
  }
}
