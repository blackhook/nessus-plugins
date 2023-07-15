#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0701. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119437);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0256", "CVE-2013-0269");
  script_bugtraq_id(57785, 57899);
  script_xref(name:"RHSA", value:"2013:0701");

  script_name(english:"RHEL 6 : ruby193-ruby, rubygem-json and rubygem-rdoc (RHSA-2013:0701)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated ruby193-ruby, rubygem-json and rubygem-rdoc packages that fix
two security issues are now available for Red Hat OpenShift Enterprise
1.1.3.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw in rubygem-json and ruby193-rubygem-json allowed remote attacks
by creating different types of malicious objects. For example, it
could initiate a denial of service attack through resource consumption
by using a JSON document to create arbitrary Ruby symbols, which were
never garbage collected. It could also be exploited to create internal
objects which could allow a SQL injection attack. (CVE-2013-0269)

It was found that documentation created by rubygem-rdoc and
ruby193-rubygem-rdoc was vulnerable to a cross-site scripting (XSS)
attack. If such documentation was accessible over a network, and a
remote attacker could trick a user into visiting a specially crafted
URL, it would lead to arbitrary web script execution in the context of
the user's session. As rubygem-rdoc and ruby193-rubygem-rdoc are used
for creating documentation for Ruby source files (such as classes,
modules, and so on), it is not a common scenario to make such
documentation accessible over the network. (CVE-2013-0256)

Red Hat would like to thank Ruby on Rails upstream for reporting
CVE-2013-0269, and Eric Hodel of RDoc upstream for reporting
CVE-2013-0256. Upstream acknowledges Thomas Hollstegge of Zweitag and
Ben Murphy as the original reporters of CVE-2013-0269, and Evgeny
Ermakov as the original reporter of CVE-2013-0256.

Users of Red Hat OpenShift Enterprise 1.1.3 are advised to upgrade to
these updated packages, which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0269"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");
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
  rhsa = "RHSA-2013:0701";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-debuginfo-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-devel-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-doc-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-ruby-irb-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-libs-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-tcltk-1.9.3.327-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-bigdecimal-1.1.0-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-io-console-0.3-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-json-1.5.4-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-minitest-2.5.1-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rake-0.9.2.2-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-rdoc-3.9.4-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygems-1.8.23-28.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygems-devel-1.8.23-28.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-1.7", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-1.7.3-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-debuginfo-1.7", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-json-debuginfo-1.7.3-2.el6")) flag++;
  if (rpm_exists(rpm:"rubygem-json-doc-1.7", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rubygem-json-doc-1.7.3-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rdoc-3.8-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rdoc-doc-3.8-9.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby193-ruby / ruby193-ruby-debuginfo / ruby193-ruby-devel / etc");
  }
}
