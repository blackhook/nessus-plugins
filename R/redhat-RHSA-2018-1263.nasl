#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1263. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109566);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2017-15010", "CVE-2018-3728");
  script_xref(name:"RHSA", value:"2018:1263");

  script_name(english:"RHEL 7 : Red Hat Mobile Application Platform 4.6.0 (RHSA-2018:1263)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Mobile Application Platform 4.6.0 release - RPMs

Red Hat Mobile Application Platform (RHMAP) 4.6 is delivered as a set
of container images.

In addition to the images, several components are delivered as RPMs :

* OpenShift templates used to deploy an RHMAP Core and MBaaS

* The fh-system-dump-tool allows you to analyze all the projects
running in an OpenShift cluster and reports any problems discovered.
For more information, see the Operations Guide.

The following RPMs are included in the RHMAP container images, and are
provided here only for completeness :

* The Nagios server, which is used to monitor the status of RHMAP
components, is installed inside the Nagios container image.

This release serves as an update for Red Hat Mobile Application
Platform 4.5.6. It includes bug fixes and enhancements. Refer to the
Red Hat Mobile Application Platform 4.6.0 Release Notes for
information about the most significant bug fixes and enhancements
included in this release.

Nagios is a program that monitors hosts and services on your network,
and has the ability to send email or page alerts when a problem arises
or is resolved.

Security Fix(es) :

* nodejs-tough-cookie: Regular expression denial of service
(CVE-2017-15010)

* hoek: Prototype pollution in utilities function (CVE-2018-3728)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-15010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3728"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fh-system-dump-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fping-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-by_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-dig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-disk_smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-file_age");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-flexlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-fping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-game");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-hpjd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-icmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ide_smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ifoperstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ifstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ircd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-mrtg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-mrtgtraf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-nt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-nwstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-overcr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-procs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-real");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-rpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-sensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-swap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-tcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-ups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-uptime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-users");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-plugins-wave");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Crypt-CBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Crypt-DES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Crypt-DES-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Net-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:phantomjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:phantomjs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-meld3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-meld3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qstat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:radiusclient-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:radiusclient-ng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:radiusclient-ng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:radiusclient-ng-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhmap-fh-openshift-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhmap-mod_authnz_external");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhmap-mod_authnz_external-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sendEmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ssmtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ssmtp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:supervisor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/04");
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
  rhsa = "RHSA-2018:1263";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"rhmap-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Red Hat Mobile Application Platform 4.6.0");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fh-system-dump-tool-1.0.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fping-3.10-4.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fping-debuginfo-3.10-4.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-4.0.8-8.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-common-4.0.8-8.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-debuginfo-4.0.8-8.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-devel-4.0.8-8.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-all-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-apt-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-breeze-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-by_ssh-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-cluster-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dbi-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-debuginfo-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dhcp-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dig-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-disk-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-disk_smb-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dns-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dummy-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-file_age-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-flexlm-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-fping-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-game-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-hpjd-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-http-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-icmp-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ide_smart-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ifoperstatus-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ifstatus-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ircd-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ldap-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-load-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-log-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mailq-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mrtg-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mrtgtraf-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mysql-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-nagios-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-nt-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ntp-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ntp-perl-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-nwstat-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-oracle-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-overcr-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-perl-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-pgsql-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ping-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-procs-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-radius-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-real-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-rpc-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-sensors-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-smtp-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-snmp-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ssh-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-swap-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-tcp-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-time-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ups-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-uptime-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-users-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-wave-2.0.3-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", reference:"perl-Crypt-CBC-2.33-2.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perl-Crypt-DES-2.05-20.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perl-Crypt-DES-debuginfo-2.05-20.el7map")) flag++;
  if (rpm_check(release:"RHEL7", reference:"perl-Net-SNMP-6.0.1-7.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"phantomjs-1.9.7-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"phantomjs-debuginfo-1.9.7-3.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-meld3-0.6.10-1.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-meld3-debuginfo-0.6.10-1.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qstat-2.11-13.20080912svn311.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qstat-debuginfo-2.11-13.20080912svn311.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-0.5.6-9.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-debuginfo-0.5.6-9.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-devel-0.5.6-9.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-utils-0.5.6-9.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"redis-2.8.21-2.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"redis-debuginfo-2.8.21-2.el7map")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhmap-fh-openshift-templates-4.6.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rhmap-mod_authnz_external-3.3.1-7.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rhmap-mod_authnz_external-debuginfo-3.3.1-7.el7map")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sendEmail-1.56-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ssmtp-2.64-14.el7map")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ssmtp-debuginfo-2.64-14.el7map")) flag++;
  if (rpm_check(release:"RHEL7", reference:"supervisor-3.1.3-3.el7map")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fh-system-dump-tool / fping / fping-debuginfo / nagios / etc");
  }
}
