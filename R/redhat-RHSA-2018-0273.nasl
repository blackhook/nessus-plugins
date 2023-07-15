#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0273. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106615);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2016-1000111");
  script_xref(name:"RHSA", value:"2018:0273");

  script_name(english:"RHEL 6 / 7 : Red Hat Satellite 6 (RHSA-2018:0273)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Satellite 6.2 for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

[Updated 06 Feb 2018] This advisory has been updated with the correct
solution. The packages included in this revised update have not been
changed in any way from the packages included in the original
advisory.

Red Hat Satellite is a system management solution that allows
organizations to configure and maintain their systems without the
necessity to provide public Internet access to their servers or other
client systems. It performs provisioning and configuration management
of predefined standard operating environments.

Twisted is an event-based framework for internet applications. Twisted
Web is a complete web server, aimed at hosting web applications using
Twisted and Python, but fully able to serve static pages too.

Security Fix(es) :

* It was discovered that python-twisted-web used the value of the
Proxy header from HTTP requests to initialize the HTTP_PROXY
environment variable for CGI scripts, which in turn was incorrectly
used by certain HTTP client implementations to configure the proxy for
outgoing HTTP requests. A remote attacker could possibly use this flaw
to redirect HTTP requests performed by a CGI script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-1000111)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue.

This update fixes the following bugs :

* Upgrades from Satellite 6.2 to Satellite 6.3 were failing due to the
use of certificates with custom authorities. These upgrade paths now
work. (BZ# 1523880, BZ#1527963)

* Additional tooling is provided to support data validation when
upgrading from Satellite 6.2 to Satellite 6.3. (BZ#1519904)

* Several memory usage bugs in goferd and qpid have been resolved.
(BZ# 1319165, BZ#1318015, BZ#1492355, BZ#1491160, BZ#1440235)

* The performance of Puppet reporting and errata applicability has
been improved. (BZ#1465146, BZ#1482204)

* Upgrading from 6.2.10 to 6.2.11 without correctly stopping services
can cause the upgrade to fail on removing qpid data. This case is now
handled properly. (BZ#1482539)

* The cipher suites for the Puppet server can now be configured by the
installation process. (BZ#1491363)

* The default cipher suite for the Apache server is now more secure by
default. (BZ#1467434)

* The Pulp server contained in Satellite has been enhanced to better
handle concurrent processing of errata applicability for a single host
and syncing Puppet repositories. (BZ#1515195, BZ#1421594)

* VDC subscriptions create guest pools which are for a single host
only. Administrators were attaching these pools to activation keys
which was incorrect. The ability to do this has been disabled.
(BZ#1369189)

* Satellite was not susceptible to RHSA-2016:1978 but security
scanners would incorrectly flag this as an issue. The package from
this errata is now delivered in the Satellite channel to avoid these
false positives. (BZ# 1497337)

* OpenScap report parsing resulted in a memory leak. This leak has
been fixed. (BZ#1454743)

* The validation on the length of names for docker containers and
repositories was too restrictive. Names can now be longer.
(BZ#1424689)

Users of Red Hat Satellite are advised to upgrade to these updated
packages, which fix these bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-1000111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0273"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-rackspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libqpid-dispatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-agent-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-oid_validation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-repoauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-streamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-debug-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello_ostree");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0273";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"satellite-6") || rpm_exists(release:"RHEL7", rpm:"satellite-6"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Red Hat Satellite 6");

  if (rpm_check(release:"RHEL6", reference:"candlepin-0.9.54.26-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"candlepin-selinux-0.9.54.26-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-compute-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-debug-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-ec2-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-gce-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-installer-1.11.0.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-installer-katello-3.0.0.101-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-libvirt-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-openstack-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-ovirt-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-postgresql-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-rackspace-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"foreman-vmware-1.11.0.86-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-3.0.0-33.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-capsule-3.0.0-33.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-common-3.0.0-33.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-debug-3.0.0-33.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-installer-base-3.0.0.101-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-service-3.0.0-33.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libqpid-dispatch-0.4-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-admin-client-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-admin-extensions-2.8.7.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-plugins-2.8.7.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-puppet-tools-2.8.7.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-selinux-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pulp-server-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-agent-lib-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-bindings-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-client-lib-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-common-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-oid_validation-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-puppet-common-2.8.7.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-repoauth-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-pulp-streamer-2.8.7.18-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-qpid-proton-0.9-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-debuginfo-0.4-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-router-0.4-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-dispatch-tools-0.4-27.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-c-0.9-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.9-21.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-smart_proxy_openscap-0.5.3.9-2.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-6.2.14-4.0.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-capsule-6.2.14-4.0.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-cli-6.2.14-4.0.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"satellite-debug-tools-6.2.14-4.0.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tfm-rubygem-foreman_theme_satellite-0.1.47.2-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tfm-rubygem-katello-3.0.0.162-1.el6sat")) flag++;

  if (rpm_check(release:"RHEL7", reference:"candlepin-0.9.54.26-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"candlepin-selinux-0.9.54.26-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-compute-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-debug-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ec2-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-gce-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-1.11.0.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-katello-3.0.0.101-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-libvirt-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-openstack-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ovirt-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-postgresql-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-rackspace-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-vmware-1.11.0.86-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-3.0.0-33.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-capsule-3.0.0-33.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-common-3.0.0-33.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-debug-3.0.0-33.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-base-3.0.0.101-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-service-3.0.0-33.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libqpid-dispatch-0.4-27.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-admin-client-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-admin-extensions-2.8.7.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-plugins-2.8.7.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-tools-2.8.7.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-selinux-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-server-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-agent-lib-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-bindings-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-client-lib-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-common-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-oid_validation-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-puppet-common-2.8.7.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-repoauth-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-streamer-2.8.7.18-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-qpid-proton-0.9-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-twisted-web-12.1.0-5.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-debuginfo-0.4-27.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-router-0.4-27.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-dispatch-tools-0.4-27.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-c-0.9-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qpid-proton-debuginfo-0.9-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_openscap-0.5.3.9-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-6.2.14-4.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-capsule-6.2.14-4.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-cli-6.2.14-4.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-debug-tools-6.2.14-4.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_theme_satellite-0.1.47.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-katello-3.0.0.162-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-katello_ostree-3.0.0.162-1.el7sat")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "candlepin / candlepin-selinux / foreman / foreman-compute / etc");
  }
}
