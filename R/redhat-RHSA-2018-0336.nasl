#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0336. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107053);
  script_version("3.7");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2013-6459", "CVE-2014-8183", "CVE-2016-1669", "CVE-2016-3693", "CVE-2016-3696", "CVE-2016-3704", "CVE-2016-4451", "CVE-2016-4995", "CVE-2016-4996", "CVE-2016-6319", "CVE-2016-8639", "CVE-2016-9593", "CVE-2016-9595", "CVE-2017-15699", "CVE-2017-2295", "CVE-2017-2667", "CVE-2017-2672");
  script_xref(name:"RHSA", value:"2018:0336");

  script_name(english:"RHEL 7 : Satellite Server (RHSA-2018:0336)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Satellite.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Satellite is a systems management tool for Linux-based
infrastructure. It allows for provisioning, remote management, and
monitoring of multiple Linux deployments with a single centralized
tool.

This update provides Satellite 6.3 packages for Red Hat Enterprise
Linux 7 Satellite server. For the full list of new features provided
by Satellite 6.3, see the Release Notes linked to in the references
section. See the Satellite 6 Installation Guide for detailed
instructions on how to install a new Satellite 6.3 environment, or the
Satellite 6 Upgrading and Updating guide for detailed instructions on
how to upgrade from prior versions of Satellite 6.

All users who require Satellite version 6.3 are advised to install
these new packages.

Security Fix(es) :

* V8: integer overflow leading to buffer overflow in Zone::New
(CVE-2016-1669)

* rubygem-will_paginate: XSS vulnerabilities (CVE-2013-6459)

* foreman: models with a 'belongs_to' association to an Organization
do not verify association belongs to that Organization (CVE-2014-8183)

* foreman: inspect in a provisioning template exposes sensitive
controller information (CVE-2016-3693)

* pulp: Unsafe use of bash $RANDOM for NSS DB password and seed
(CVE-2016-3704)

* foreman: privilege escalation through Organization and Locations API
(CVE-2016-4451)

* foreman: inside discovery-debug, the root password is displayed in
plaintext (CVE-2016-4996)

* foreman: Persistent XSS in Foreman remote execution plugin
(CVE-2016-6319)

* foreman: Stored XSS via organization/location with HTML in name
(CVE-2016-8639)

* katello-debug: Possible symlink attacks due to use of predictable
file names (CVE-2016-9595)

* rubygem-hammer_cli: no verification of API server's SSL certificate
(CVE-2017-2667)

* foreman: Image password leak (CVE-2017-2672)

* pulp: Leakage of CA key in pulp-qpid-ssl-cfg (CVE-2016-3696)

* foreman: Information disclosure in provisioning template previews
(CVE-2016-4995)

* foreman-debug: missing obfuscation of sensitive information
(CVE-2016-9593)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Randy Barlow (RedHat) for reporting
CVE-2016-3704 and Sander Bos for reporting CVE-2016-3696. The
CVE-2014-8183 issue was discovered by Eric Helms (Red Hat); the
CVE-2016-3693 and CVE-2016-4995 issues were discovered by Dominic
Cleal (Red Hat); the CVE-2016-4451 and CVE-2016-6319 issues were
discovered by Marek Hulan (Red Hat); the CVE-2016-4996 issue was
discovered by Thom Carlin (Red Hat); the CVE-2016-8639 issue was
discovered by Sanket Jagtap (Red Hat); the CVE-2016-9595 issue was
discovered by Evgeni Golov (Red Hat); the CVE-2017-2667 issue was
discovered by Tomas Strachota (Red Hat); and the CVE-2016-9593 issue
was discovered by Pavel Moravec (Red Hat)."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.3/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ae701e8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-6459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-1669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-2672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15699"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat-tftpboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-rackspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hiera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-client-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-installer-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kobo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-oid_validation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-ostree-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-repoauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-streamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zope-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zope-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-access-insights-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_remote_isc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery_image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_remote_execution_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-debug-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-bastion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-redhat_access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_csv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello_ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt_provision_plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dynflow_core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0336";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"spacewalk-admin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL7", reference:"candlepin-2.1.14-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"candlepin-selinux-2.1.14-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-bootloaders-redhat-201801241201-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-bootloaders-redhat-tftpboot-201801241201-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-cli-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-compute-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-debug-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-discovery-image-3.4.4-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ec2-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-gce-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-1.15.6.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-katello-3.4.5.26-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-libvirt-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-openstack-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-ovirt-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-postgresql-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-proxy-1.15.6.4-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-proxy-content-3.4.5-15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-rackspace-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-selinux-1.15.6.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-vmware-1.15.6.34-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"hiera-1.3.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-3.4.5-15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-certs-tools-2.4.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-client-bootstrap-1.5.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-common-3.4.5-15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-debug-3.4.5-15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-installer-base-3.4.5.26-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-selinux-3.0.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"katello-service-3.4.5-15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kobo-0.5.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-admin-client-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-docker-admin-extensions-2.4.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-docker-plugins-2.4.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-katello-1.0.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-ostree-admin-extensions-1.2.1.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-ostree-plugins-1.2.1.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-admin-extensions-2.13.4-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-plugins-2.13.4-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-puppet-tools-2.13.4-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-admin-extensions-2.13.4.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-rpm-plugins-2.13.4.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-selinux-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"pulp-server-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppet-foreman_scap_client-0.3.16-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-bindings-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-client-lib-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-common-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-docker-common-2.4.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-oid_validation-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-ostree-common-1.2.1.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-puppet-common-2.13.4-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-repoauth-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-rpm-common-2.13.4.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pulp-streamer-2.13.4.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-zope-interface-4.0.5-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-zope-interface-debuginfo-4.0.5-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-access-insights-puppet-0.0.9-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-foreman_scap_client-0.3.0-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo-2.0.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo_parsers-0.1.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo_wizards-0.0.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_dhcp_remote_isc-0.0.2.1-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery-1.0.4-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery_image-1.0.9-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_dynflow-0.1.10-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_openscap-0.6.9-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_pulp-1.3.0-1.git.0.b5c2768.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_remote_execution_ssh-0.1.6-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tilt-1.3.7-2.git.0.3b416c9.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-6.3.0-23.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-capsule-6.3.0-23.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-cli-6.3.0-23.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-common-6.3.0-23.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-debug-tools-6.3.0-23.0.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"satellite-installer-6.3.0.12-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-bastion-5.1.1.4-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman-redhat_access-2.0.13-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman-tasks-0.9.6.4-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman-tasks-core-0.1.8-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_bootdisk-10.0.2.2-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_discovery-9.1.5.3-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_docker-3.1.0.3-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_hooks-0.3.14-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_openscap-0.7.11-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_remote_execution-1.3.7.2-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_remote_execution_core-1.0.6-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_templates-5.0.1-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_theme_satellite-1.0.4.16-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-foreman_virt_who_configure-0.1.9-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli-0.11.0.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_csv-2.3.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman-0.11.0.5-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_admin-0.0.8-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_bootdisk-0.1.3.3-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_discovery-1.0.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_docker-0.0.6-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_openscap-0.1.5-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_remote_execution-0.0.6-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_tasks-0.0.12-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_foreman_virt_who_configure-0.0.3-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-hammer_cli_katello-0.11.3.5-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-katello-3.4.5.58-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-katello_ostree-3.4.5.58-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-ovirt_provision_plugin-1.0.2-1.fm1_15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"tfm-rubygem-smart_proxy_dynflow_core-0.1.10-1.fm1_15.el7sat")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "candlepin / candlepin-selinux / foreman / etc");
  }
}
