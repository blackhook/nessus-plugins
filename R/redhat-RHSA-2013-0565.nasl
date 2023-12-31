#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0565. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76657);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4462");
  script_bugtraq_id(58336);
  script_xref(name:"RHSA", value:"2013:0565");

  script_name(english:"RHEL 6 : MRG (RHSA-2013:0565)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Grid component packages that fix one security issue, multiple
bugs, and add various enhancements are now available for Red Hat
Enterprise MRG 2.3 for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a
next-generation IT infrastructure for enterprise computing. MRG offers
increased performance, reliability, interoperability, and faster
computing for enterprise customers.

MRG Grid provides high-throughput computing and enables enterprises to
achieve higher peak computing capacity as well as improved
infrastructure utilization by leveraging their existing technology to
build high performance grids. MRG Grid provides a job-queueing
mechanism, scheduling policy, and a priority scheme, as well as
resource monitoring and resource management. Users submit their jobs
to MRG Grid, where they are placed into a queue. MRG Grid then chooses
when and where to run the jobs based upon a policy, carefully monitors
their progress, and ultimately informs the user upon completion.

It was found that attempting to remove a job via
'/usr/share/condor/aviary/jobcontrol.py' with CPROC in square brackets
caused condor_schedd to crash. If aviary_query_server was configured
to listen to public interfaces, this could allow a remote attacker to
cause a denial of service condition in condor_schedd. While
condor_schedd was restarted by the condor_master process after each
exit, condor_master would throttle back restarts after each crash.
This would slowly increment to the defined MASTER_BACKOFF_CEILING
value (3600 seconds/1 hour, by default). (CVE-2012-4462)

The CVE-2012-4462 issue was discovered by Daniel Horak of the Red Hat
Enterprise MRG Quality Engineering Team.

These updated packages for Red Hat Enterprise Linux 6 provide numerous
enhancements and bug fixes for the Grid component of MRG. Some of the
most important enhancements include :

* Release of HTCondor 7.8

* OS integration with control groups (cgroups)

* Kerberos integration and HTML5 interactivity in the management
console

* Historical data reporting in the management console as Technology
Preview

* Job data availability from MongoDB as Technology Preview

* Updated EC2 AMI and instance tagging support

* Enhanced negotiation and accounting

* Enhanced DAG workflow management

* Enhancements to configuration inspection, node inventory, and
configuration of walk-in or dynamic resources

* High availability for Aviary

Space precludes documenting all of these changes in this advisory.
Refer to the Red Hat Enterprise MRG 2 Technical Notes document,
available shortly from the link in the References section, for
information on these changes.

All users of the Grid capabilities of Red Hat Enterprise MRG are
advised to upgrade to these updated packages, which correct this
issue, and fix the bugs and add the enhancements noted in the Red Hat
Enterprise MRG 2 Technical Notes."
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_MRG/2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9345c1b9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4462"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-cluster-resource-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-deltacloud-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-ec2-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-ec2-enhanced-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-job-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-low-latency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-plumage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-base-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-condorec2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-condorutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallabyclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-condor-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rhubarb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-spqr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spqr-gen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby-utils");
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
  rhsa = "RHSA-2013:0565";
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

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-aviary-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-aviary-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-classads-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-classads-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-cluster-resource-agent-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-cluster-resource-agent-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-debuginfo-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-debuginfo-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-deltacloud-gahp-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-ec2-enhanced-1.3.0-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-ec2-enhanced-hooks-1.3.0-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-job-hooks-1.5-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-kbdd-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-kbdd-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-low-latency-1.2-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-plumage-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-plumage-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"condor-qmf-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-qmf-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"condor-vm-gahp-7.8.8-0.4.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-wallaby-base-db-1.25-1.el6_3")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-wallaby-client-5.0.5-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"condor-wallaby-tools-5.0.5-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"cumin-0.1.5675-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"deltacloud-core-0.5.0-11.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"deltacloud-core-doc-0.5.0-11.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"deltacloud-core-rhevm-0.5.0-11.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-condorec2e-1.3.0-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-condorutils-1.5-6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-wallaby-0.16.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-wallabyclient-5.0.5-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby-condor-wallaby-5.0.5-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-nokogiri-1.5.0-0.9.beta4.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby-rhubarb-0.4.3-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby-spqr-0.3.6-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby-wallaby-0.16.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-nokogiri-1.5.0-0.9.beta4.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rubygem-nokogiri-debuginfo-1.5.0-0.9.beta4.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-nokogiri-doc-1.5.0-0.9.beta4.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-rack-1.3.0-3.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sesame-1.0-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sesame-1.0-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sesame-debuginfo-1.0-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sesame-debuginfo-1.0-8.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spqr-gen-0.3.6-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wallaby-0.16.3-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"wallaby-utils-0.16.3-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "condor / condor-aviary / condor-classads / etc");
  }
}
