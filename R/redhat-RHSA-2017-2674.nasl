#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2674. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103349);
  script_version("3.11");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-1000117", "CVE-2017-7552", "CVE-2017-7553", "CVE-2017-7554");
  script_xref(name:"RHSA", value:"2017:2674");

  script_name(english:"RHEL 7 : Mobile Application Platform (RHSA-2017:2674)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update is now available for Red Hat Mobile Application Platform
4.5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Mobile Application Platform (RHMAP) 4.5 is delivered as a set
of Docker-formatted container images.

In addition to the images, several components are delivered as RPMs :

* OpenShift templates used to deploy an RHMAP Core and MBaaS

* The fh-system-dump-tool allows you to analyze all the projects
running in an OpenShift cluster and reports any problems discovered.
For more information, see the Operations Guide

The following RPMs are included in the RHMAP container images, and are
provided here only for completeness :

* The Nagios server, which is used to monitor the status of RHMAP
components, is installed inside the Nagios container image.

This release serves as an update for Red Hat Mobile Application
Platform 4.4.3. It includes bug fixes and enhancements. Refer to the
Red Hat Mobile Application Platform 4.5.0 Release Notes for
information about the most significant bug fixes and enhancements
included in this release.

Nagios is a program that monitors hosts and services on your network,
and has the ability to send email or page alerts when a problem arises
or is resolved.

Security Fix(es) :

* A shell command injection flaw related to the handling of 'ssh' URLs
has been discovered in Git. An attacker could use this flaw to execute
shell commands with the privileges of the user running the Git client,
for example, when performing a 'clone' action on a malicious
repository or a legitimate repository containing a malicious commit.
(CVE-2017-1000117)

* A flaw was discovered in the file editor of millicore which allows
files to be executed as well as created. An attacker could use this
flaw to compromise other users or teams projects stored in source
control management of the RHMAP Core installation. (CVE-2017-7552)

* The external_request api call in App Studio (millicore) allows
server side request forgery (SSRF). An attacker could use this flaw to
probe the network internal resources and access restricted endpoints.
(CVE-2017-7553)

* A flaw was found where the App Studio component of RHMAP 4.4
executes JavaScript provided by a user. An attacker could use this
flaw to execute a stored XSS attack on an application administrator
using App Studio. (CVE-2017-7554)

Red Hat would like to thank Tomas Rzepka for reporting CVE-2017-7552,
CVE-2017-7553 and CVE-2017-7554."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7554"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2017-1000117');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:2674";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"rhmap-fh-openshift-templates"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mobile Application Platform");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fh-system-dump-tool-1.0.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fping-3.10-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fping-debuginfo-3.10-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-4.0.8-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-common-4.0.8-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-debuginfo-4.0.8-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-devel-4.0.8-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-all-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-apt-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-breeze-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-by_ssh-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-cluster-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dbi-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-debuginfo-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dhcp-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dig-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-disk-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-disk_smb-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dns-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-dummy-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-file_age-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-flexlm-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-fping-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-game-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-hpjd-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-http-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-icmp-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ide_smart-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ifoperstatus-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ifstatus-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ircd-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ldap-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-load-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-log-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mailq-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mrtg-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mrtgtraf-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-mysql-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-nagios-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-nt-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ntp-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ntp-perl-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-nwstat-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-oracle-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-overcr-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-perl-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-pgsql-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ping-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-procs-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-radius-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-real-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-rpc-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-sensors-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-smtp-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-snmp-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ssh-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-swap-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-tcp-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-time-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-ups-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-uptime-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-users-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nagios-plugins-wave-2.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"perl-Crypt-CBC-2.33-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perl-Crypt-DES-2.05-20.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perl-Crypt-DES-debuginfo-2.05-20.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"perl-Net-SNMP-6.0.1-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"phantomjs-1.9.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"phantomjs-debuginfo-1.9.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-meld3-0.6.10-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-meld3-debuginfo-0.6.10-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qstat-2.11-13.20080912svn311.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qstat-debuginfo-2.11-13.20080912svn311.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-0.5.6-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-debuginfo-0.5.6-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-devel-0.5.6-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"radiusclient-ng-utils-0.5.6-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"redis-2.8.21-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"redis-debuginfo-2.8.21-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhmap-fh-openshift-templates-4.5.0-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rhmap-mod_authnz_external-3.3.1-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rhmap-mod_authnz_external-debuginfo-3.3.1-7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"sendEmail-1.56-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ssmtp-2.64-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ssmtp-debuginfo-2.64-14.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"supervisor-3.1.3-3.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fh-system-dump-tool / fping / fping-debuginfo / nagios / etc");
  }
}
