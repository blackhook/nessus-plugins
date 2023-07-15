#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2037 and 
# CentOS Errata and Security Advisory 2019:2037 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128336);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-10153");
  script_xref(name:"RHSA", value:"2019:2037");

  script_name(english:"CentOS 7 : fence-agents (CESA-2019:2037)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for fence-agents is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The fence-agents packages provide a collection of scripts for handling
remote power management for cluster devices. They allow failed or
unreachable nodes to be forcibly restarted and removed from the
cluster.

Security Fix(es) :

* fence-agents: mis-handling of non-ASCII characters in guest comment
fields (CVE-2019-10153)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?407d076f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fence-agents packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10153");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-aliyun-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-all-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-amt-ws-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-apc-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-apc-snmp-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-aws-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-azure-arm-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-bladecenter-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-brocade-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-cisco-mds-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-cisco-ucs-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-common-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-compute-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-drac5-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-eaton-snmp-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-emerson-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-eps-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-gce-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-heuristics-ping-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-hpblade-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ibmblade-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ifmib-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ilo-moonshot-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ilo-mp-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ilo-ssh-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ilo2-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-intelmodular-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ipdu-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-ipmilan-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-kdump-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-mpath-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-redfish-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-rhevm-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-rsa-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-rsb-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-sbd-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-scsi-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-virsh-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-vmware-rest-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-vmware-soap-4.2.1-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"fence-agents-wti-4.2.1-24.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc");
}
