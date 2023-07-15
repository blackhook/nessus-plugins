#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0330. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21288);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_xref(name:"RHSA", value:"2006:0330");

  script_name(english:"RHEL 4 : thunderbird (RHSA-2006:0330)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix various bugs are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 24 Apr 2006] The erratum text has been updated to include the
details of additional issues that were fixed by these erratum packages
but which were not public at the time of release. No changes have been
made to the packages.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several bugs were found in the way Thunderbird processes malformed
JavaScript. A malicious HTML mail message could modify the content of
a different open HTML mail message, possibly stealing sensitive
information or conducting a cross-site scripting attack. Please note
that JavaScript support is disabled by default in Thunderbird.
(CVE-2006-1731, CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Thunderbird processes certain
JavaScript actions. A malicious HTML mail message could execute
arbitrary JavaScript instructions with the permissions of 'chrome',
allowing the page to steal sensitive information or install browser
malware. Please note that JavaScript support is disabled by default in
Thunderbird. (CVE-2006-0292, CVE-2006-0296, CVE-2006-1727,
CVE-2006-1728, CVE-2006-1733, CVE-2006-1734, CVE-2006-1735,
CVE-2006-1742)

Several bugs were found in the way Thunderbird processes malformed
HTML mail messages. A carefully crafted malicious HTML mail message
could cause the execution of arbitrary code as the user running
Thunderbird. (CVE-2006-0748, CVE-2006-0749, CVE-2006-1724,
CVE-2006-1730, CVE-2006-1737, CVE-2006-1738, CVE-2006-1739,
CVE-2006-1790)

A bug was found in the way Thunderbird processes certain inline
content in HTML mail messages. It may be possible for a remote
attacker to send a carefully crafted mail message to the victim, which
will fetch remote content, even if Thunderbird is configured not to
fetch remote content. (CVE-2006-1045)

A bug was found in the way Thunderbird executes in-line mail
forwarding. If a user can be tricked into forwarding a maliciously
crafted mail message as in-line content, it is possible for the
message to execute JavaScript with the permissions of 'chrome'.
(CVE-2006-0884)

Users of Thunderbird are advised to upgrade to these updated packages
containing Thunderbird version 1.0.8, which is not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1790"
  );
  # http://www.mozilla.org/projects/security/known-
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/projects/security/known-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2006:0330"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2006:0330";
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
  if (rpm_check(release:"RHEL4", reference:"thunderbird-1.0.8-1.4.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
  }
}
