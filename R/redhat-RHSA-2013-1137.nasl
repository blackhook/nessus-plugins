#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1137. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119342);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4073");
  script_xref(name:"RHSA", value:"2013:1137");

  script_name(english:"RHEL 6 : ruby193-ruby (RHSA-2013:1137)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated ruby193-ruby packages that fix one security issue are now
available for Red Hat OpenShift Enterprise 1.2.2.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in Ruby's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. An
attacker could potentially exploit this flaw to conduct
man-in-the-middle attacks to spoof SSL servers. Note that to exploit
this issue, an attacker would need to obtain a carefully-crafted
certificate signed by an authority that the client trusts.
(CVE-2013-4073)

All users of Red Hat OpenShift Enterprise 1.2.2 are advised to upgrade
to these updated packages, which resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ruby-lang.org/en/news/2013/06/27/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4073"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/18");
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
  rhsa = "RHSA-2013:1137";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-debuginfo-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-devel-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-doc-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-ruby-irb-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-libs-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-ruby-tcltk-1.9.3.448-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-bigdecimal-1.1.0-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-io-console-0.3-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-json-1.5.5-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rake-0.9.2.2-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby193-rubygem-rdoc-3.9.5-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygems-1.8.23-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygems-devel-1.8.23-38.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby193-ruby / ruby193-ruby-debuginfo / ruby193-ruby-devel / etc");
  }
}
