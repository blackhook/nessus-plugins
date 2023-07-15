#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1136. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119341);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-2119", "CVE-2013-4136");
  script_xref(name:"RHSA", value:"2013:1136");

  script_name(english:"RHEL 6 : rubygem-passenger (RHSA-2013:1136)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated rubygem-passenger packages that fix two security issues are
now available for Red Hat OpenShift Enterprise 1.2.2.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

rubygem-passenger is a web server for Ruby, Python and Node.js
applications.

The rubygem-passenger gem created and re-used temporary directories
and files in an insecure fashion. A local attacker could use these
flaws to conduct a denial of service attack, take over the operation
of the application or, potentially, execute arbitrary code with the
privileges of the user running rubygem-passenger. (CVE-2013-2119,
CVE-2013-4136)

Note: By default, OpenShift Enterprise uses polyinstantiation (per
user) for the /tmp/ directory, thereby minimizing the risk and impact
of exploitation by local attackers of both CVE-2013-2119 and
CVE-2013-4136.

The CVE-2013-2119 issue was discovered by Michael Scherer of the Red
Hat Regional IT team.

The following packages are included with this update as dependencies
of the updated Ruby 1.8 passenger packages :

rubygem-spruz-0.2.5-4.el6op rubygem-file-tail-1.0.5-4.el6op

Users of Red Hat OpenShift Enterprise 1.2.2 are advised to upgrade to
these updated packages, which correct these issues. After installing
the updated packages, manual action is required before the update
takes effect. Refer to the Solution section for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-2119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4136"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-file-tail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-file-tail-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-spruz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-spruz-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:1136";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_passenger-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-mod_passenger-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-debuginfo-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-devel-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-doc-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-libs-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-file-tail-1.0.5-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-file-tail-doc-1.0.5-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-debuginfo-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-devel-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-doc-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-native-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-passenger-native-libs-3.0.21-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-spruz-0.2.5-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-spruz-doc-0.2.5-4.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_passenger / ruby193-mod_passenger / ruby193-rubygem-passenger / etc");
  }
}
