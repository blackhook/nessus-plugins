#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0562. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76655);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4446", "CVE-2012-4458", "CVE-2012-4459");
  script_xref(name:"RHSA", value:"2013:0562");

  script_name(english:"RHEL 6 : MRG (RHSA-2013:0562)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Messaging component packages that fix multiple security
issues, several bugs, and add various enhancements are now available
for Red Hat Enterprise MRG 2.3 for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a
next-generation IT infrastructure for enterprise computing. MRG offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

MRG Messaging is a high-speed reliable messaging distribution for
Linux based on AMQP (Advanced Message Queuing Protocol), an open
protocol standard for enterprise messaging that is designed to make
mission critical messaging widely available as a standard service, and
to make enterprise messaging interoperable across platforms,
programming languages, and vendors. MRG Messaging includes an AMQP
0-10 messaging broker; AMQP 0-10 client libraries for C++, Java JMS,
and Python; as well as persistence libraries and management tools.

It was found that the Apache Qpid daemon (qpidd) treated AMQP
connections with the federation_tag attribute set as a
broker-to-broker connection, rather than a client-to-server
connection. This resulted in the source user ID of messages not being
checked. A client that can establish an AMQP connection with the
broker could use this flaw to bypass intended authentication. For
Condor users, if condor-aviary is installed, this flaw could be used
to submit jobs that would run as any user (except root, as Condor does
not run jobs as root). (CVE-2012-4446)

It was found that the AMQP type decoder in qpidd allowed arbitrary
data types in certain messages. A remote attacker could use this flaw
to send a message containing an excessively large amount of data,
causing qpidd to allocate a large amount of memory. qpidd would then
be killed by the Out of Memory killer (denial of service).
(CVE-2012-4458)

An integer overflow flaw, leading to an out-of-bounds read, was found
in the Qpid qpid::framing::Buffer::checkAvailable() function. An
unauthenticated, remote attacker could send a specially crafted
message to Qpid, causing it to crash. (CVE-2012-4459)

The CVE-2012-4446, CVE-2012-4458, and CVE-2012-4459 issues were
discovered by Florian Weimer of the Red Hat Product Security Team.

This update also fixes several bugs and adds enhancements.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

All users of the Messaging capabilities of Red Hat Enterprise MRG are
advised to upgrade to these updated packages, which resolve these
issues, and fix the bugs and add the enhancements noted in the Red Hat
Enterprise MRG 2 Technical Notes. After installing the updated
packages, stop the cluster by either running 'service qpidd stop' on
all nodes, or 'qpid-cluster --all-stop' on any one of the cluster
nodes. Once stopped, restart the cluster with 'service qpidd start' on
all nodes for the update to take effect."
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_MRG/2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9345c1b9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4458"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xqilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xqilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xqilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xqilla-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:0562";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", reference:"cumin-messaging-0.1.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mrg-release-2.3.0-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-qpid-0.18-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-qmf-0.18-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-saslwrapper-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-ssl-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-ssl-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-debuginfo-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-debuginfo-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-ssl-0.18-14.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-0.18-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-0.18-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-debuginfo-0.18-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-debuginfo-0.18-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-tests-0.18-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-tools-0.18-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-qpid-qmf-0.18-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-saslwrapper-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rake-0.8.7-2.1.el6")) flag++;
  if (rpm_exists(rpm:"rubygems-1.8", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rubygems-1.8.16-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"saslwrapper-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"saslwrapper-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"saslwrapper-debuginfo-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"saslwrapper-debuginfo-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"saslwrapper-devel-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"saslwrapper-devel-0.18-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-c-3.0.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-c-debuginfo-3.0.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-c-devel-3.0.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xerces-c-doc-3.0.1-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xqilla-2.2.3-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xqilla-debuginfo-2.2.3-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xqilla-devel-2.2.3-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xqilla-doc-2.2.3-8.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cumin-messaging / mrg-release / python-qpid / python-qpid-qmf / etc");
  }
}
