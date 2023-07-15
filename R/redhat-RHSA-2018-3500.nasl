#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3500. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118745);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2018-17204", "CVE-2018-17205", "CVE-2018-17206");
  script_xref(name:"RHSA", value:"2018:3500");

  script_name(english:"RHEL 7 : openvswitch (RHSA-2018:3500)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for openvswitch is now available for Fast Datapath for Red
Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Open vSwitch provides standard network bridging functions and support
for the OpenFlow protocol for remote per-flow control of traffic.

Security Fix(es) :

* openvswitch: Mishandle of group mods in lib/
ofp-util.c:parse_group_prop_ntr_selection_method() allows for
assertion failure (CVE-2018-17204)

* openvswitch: Error during bundle commit in ofproto/
ofproto.c:ofproto_rule_insert__() allows for crash (CVE-2018-17205)

* openvswitch: Buffer over-read in lib/ofp-actions.c:decode_bundle()
(CVE-2018-17206)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Bug Fix(es) :

* Previously, when the ovs-vswitchd service restarted, an error
displayed with many open files. With this update, the number of
sockets opened by ovs-vswitchd is decreased. As a result, the
described problem no longer occurs. (BZ#1526306)

* Previously, when OpenvSwitch service was reloaded, the default flow
was not removed and it became part of the final flow table. With this
update, the default flow rule is no longer added after a service
reload. As a result, the described problem no longer occurs.
(BZ#1626096)

Enhancement(s) :

* With this update, the pmd-rxq-assign configuration has been added to
Poll Mode Drivers (PMDs) cores. This allows users to select a
round-robin assignment. (BZ#1616001)

* With this update the ovs-appctl connection-status command has been
introduced to the ovs-appctl utility. The command enables to monitor
hypervisor (HV) south bound database (SBDB) connection status. Layered
products can now check if the ovn-controller is properly connected to
a central node. (BZ#1593804)

* With this update, a support for the Dynamic Host Configuration
Protocol (DHCP) option 252 has been added to Open Virtual Network
(OVN) Native DHCP. (BZ#1641765)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:3500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-17204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-17205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-17206"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/06");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:3500";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-debuginfo-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-devel-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-ovn-central-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-ovn-common-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-ovn-host-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-ovn-vtep-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openvswitch-test-2.9.0-70.el7fdp.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-openvswitch-2.9.0-70.el7fdp.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch / openvswitch-debuginfo / openvswitch-devel / etc");
  }
}
