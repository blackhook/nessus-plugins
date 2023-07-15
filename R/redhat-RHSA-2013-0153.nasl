#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0153. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119429);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0156");
  script_xref(name:"RHSA", value:"2013:0153");

  script_name(english:"RHEL 6 : Ruby on Rails (RHSA-2013:0153)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rubygem-actionpack, rubygem-activesupport,
ruby193-rubygem-actionpack, and ruby193-rubygem-activesupport packages
that fix multiple security issues are now available for Red Hat
OpenShift Enterprise 1.0.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Ruby on Rails is a model-view-controller (MVC) framework for web
application development. Action Pack implements the controller and the
view components. Active Support provides support and utility classes
used by the Ruby on Rails framework.

Multiple flaws were found in the way Ruby on Rails performed XML
parameter parsing in HTTP requests. A remote attacker could use these
flaws to execute arbitrary code with the privileges of a Ruby on Rails
application, perform SQL injection attacks, or bypass the
authentication using a specially-created HTTP request. (CVE-2013-0156)

Red Hat is aware that a public exploit for the CVE-2013-0156 issues is
available that allows remote code execution in applications using Ruby
on Rails.

All users of Red Hat OpenShift Enterprise are advised to upgrade to
these updated packages, which correct these issues. For Red Hat
OpenShift Enterprise administrators, the openshift-broker and
openshift-console services must be restarted for this update to take
effect. Users of OpenShift are advised to update their own
applications that are running Ruby on Rails."
  );
  # https://access.redhat.com/knowledge/solutions/290903
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/solutions/290903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-0156"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails XML Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionpack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/10");
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
  rhsa = "RHSA-2013:0153";
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
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-actionpack-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-actionpack-doc-3.2.8-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activesupport-3.2.8-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-actionpack-3.0.13-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activesupport-3.0.13-2.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby193-rubygem-actionpack / ruby193-rubygem-actionpack-doc / etc");
  }
}
