#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1024. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76661);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1909");
  script_bugtraq_id(60800);
  script_xref(name:"RHSA", value:"2013:1024");

  script_name(english:"RHEL 6 : MRG (RHSA-2013:1024)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Messaging component packages that fix one security issue and
multiple bugs are now available for Red Hat Enterprise MRG 2.3 for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

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

It was discovered that the Qpid Python client library for AMQP did not
properly perform TLS/SSL certificate validation of the remote server's
certificate, even when the 'ssl_trustfile' connection option was
specified. A rogue server could use this flaw to conduct
man-in-the-middle attacks, possibly leading to the disclosure of
sensitive information. (CVE-2013-1909)

With this update, Python programs can instruct the library to validate
server certificates by specifying a path to a file containing trusted
CA certificates.

This issue was discovered by Petr Matousek of the Red Hat MRG
Messaging team.

This update also fixes multiple bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

All users of the Messaging capabilities of Red Hat Enterprise MRG 2.3
are advised to upgrade to these updated packages, which resolve the
issues noted in the Red Hat Enterprise MRG 2 Technical Notes. After
installing the updated packages, stop the cluster by either running
'service qpidd stop' on all nodes, or 'qpid-cluster --all-stop' on any
one of the cluster nodes. Once stopped, restart the cluster with
'service qpidd start' on all nodes for the update to take effect."
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?687515f3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:1024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1909"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-example");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/11");
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
  rhsa = "RHSA-2013:1024";
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

  if (rpm_check(release:"RHEL6", reference:"python-qpid-0.18-5.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-qpid-qmf-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-qmf-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-devel-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-devel-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-cpp-client-devel-docs-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-rdma-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-rdma-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-client-ssl-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-client-ssl-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-debuginfo-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-debuginfo-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-cluster-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-cluster-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-devel-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-devel-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-rdma-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-rdma-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-ssl-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-ssl-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-store-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-store-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-cpp-server-xml-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-cpp-server-xml-0.18-17.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-client-0.18-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-common-0.18-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-java-example-0.18-8.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-debuginfo-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-debuginfo-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qpid-qmf-devel-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-qmf-devel-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", reference:"qpid-tools-0.18-10.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-qpid-qmf-0.18-18.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-qpid-qmf-0.18-18.el6_4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-qpid / python-qpid-qmf / qpid-cpp-client / etc");
  }
}
