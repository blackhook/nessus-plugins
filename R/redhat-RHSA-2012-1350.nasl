#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1350. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62472);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1956", "CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");
  script_bugtraq_id(55260);
  script_xref(name:"RHSA", value:"2012:1350");

  script_name(english:"RHEL 5 / 6 : firefox (RHSA-2012:1350)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated firefox packages that fix several security issues and one bug
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-3982, CVE-2012-3988, CVE-2012-3990,
CVE-2012-3995, CVE-2012-4179, CVE-2012-4180, CVE-2012-4181,
CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
CVE-2012-4187, CVE-2012-4188)

Two flaws in Firefox could allow a malicious website to bypass
intended restrictions, possibly leading to information disclosure, or
Firefox executing arbitrary code. Note that the information disclosure
issue could possibly be combined with other flaws to achieve arbitrary
code execution. (CVE-2012-3986, CVE-2012-3991)

Multiple flaws were found in the location object implementation in
Firefox. Malicious content could be used to perform cross-site
scripting attacks, script injection, or spoofing attacks.
(CVE-2012-1956, CVE-2012-3992, CVE-2012-3994)

Two flaws were found in the way Chrome Object Wrappers were
implemented. Malicious content could be used to perform cross-site
scripting attacks or cause Firefox to execute arbitrary code.
(CVE-2012-3993, CVE-2012-4184)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.8 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Christian Holler, Jesse Ruderman,
Soroush Dalili, miaubiz, Abhishek Arya, Atte Kettunen, Johnny
Stenback, Alice White, moz_bug_r_a4, and Mariusz Mlynski as the
original reporters of these issues.

This update also fixes the following bug :

* In certain environments, storing personal Firefox configuration
files (~/.mozilla/) on an NFS share, such as when your home directory
is on a NFS share, led to Firefox functioning incorrectly, for
example, navigation buttons not working as expected, and bookmarks not
saving. This update adds a new configuration option,
storage.nfs_filesystem, that can be used to resolve this issue.

If you experience this issue :

1) Start Firefox.

2) Type 'about:config' (without quotes) into the URL bar and press the
Enter key.

3) If prompted with 'This might void your warranty!', click the 'I'll
be careful, I promise!' button.

4) Right-click in the Preference Name list. In the menu that opens,
select New -> Boolean.

5) Type 'storage.nfs_filesystem' (without quotes) for the preference
name and then click the OK button.

6) Select 'true' for the boolean value and then press the OK button.
(BZ#809571, BZ#816234)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.8 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefoxESR.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a134523f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-1956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4182"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1350";
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
  if (rpm_check(release:"RHEL5", reference:"firefox-10.0.8-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", reference:"firefox-debuginfo-10.0.8-1.el5_8", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-10.0.8-1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-debuginfo-10.0.8-1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", reference:"xulrunner-devel-10.0.8-1.el5_8")) flag++;


  if (rpm_check(release:"RHEL6", reference:"firefox-10.0.8-1.el6_3", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", reference:"firefox-debuginfo-10.0.8-1.el6_3", allowmaj:TRUE)) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-10.0.8-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-debuginfo-10.0.8-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xulrunner-devel-10.0.8-1.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo / xulrunner / xulrunner-debuginfo / etc");
  }
}
