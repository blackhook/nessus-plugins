#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:323. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17624);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0906", "CVE-2004-1380", "CVE-2004-1613", "CVE-2005-0141", "CVE-2005-0144", "CVE-2005-0147", "CVE-2005-0149", "CVE-2005-0232", "CVE-2005-0399");
  script_xref(name:"RHSA", value:"2005:323");

  script_name(english:"RHEL 2.1 / 3 : mozilla (RHSA-2005:323)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix various bugs are now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A buffer overflow bug was found in the way Mozilla processes GIF
images. It is possible for an attacker to create a specially crafted
GIF image, which when viewed by a victim will execute arbitrary code
as the victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0399 to this issue.

A bug was found in the way Mozilla displays dialog windows. It is
possible that a malicious web page which is being displayed in a
background tab could present the user with a dialog window appearing
to come from the active page. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-1380 to this
issue.

A bug was found in the way Mozilla allowed plug-ins to load privileged
content into a frame. It is possible that a malicious webpage could
trick a user into clicking in certain places to modify configuration
settings or execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0232
to this issue.

A bug was found in the way Mozilla Mail handles cookies when loading
content over HTTP regardless of the user's preference. It is possible
that a particular user could be tracked through the use of malicious
mail messages which load content over HTTP. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-0149 to this issue.

A bug was found in the way Mozilla responds to proxy auth requests. It
is possible for a malicious webserver to steal credentials from a
victims browser by issuing a 407 proxy authentication request. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0147 to this issue.

A bug was found in the way Mozilla handles certain start tags followed
by a NULL character. A malicious web page could cause Mozilla to crash
when viewed by a victim. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-1613 to this
issue.

A bug was found in the way Mozilla sets file permissions when
installing XPI packages. It is possible for an XPI package to install
some files world readable or writable, allowing a malicious local user
to steal information or execute arbitrary code. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0906 to this issue.

A bug was found in the way Mozilla loads links in a new tab which are
middle clicked. A malicious web page could read local files or modify
privileged chrom settings. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0141 to this
issue.

A bug was found in the way Mozilla displays the secure site icon. A
malicious web page can use a view-source URL targetted at a secure
page, while loading an insecure page, yet the secure site icon shows
the previous secure state. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0144 to this
issue.

Users of Mozilla are advised to upgrade to this updated package which
contains Mozilla version 1.4.4 and additional backported patches to
correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-1613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2005:323"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:323";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"galeon-1.2.13-6.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.4.4-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.4.4-1.2.3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.4.4-1.3.5")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.4.4-1.3.5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "galeon / mozilla / mozilla-chat / mozilla-devel / etc");
  }
}
