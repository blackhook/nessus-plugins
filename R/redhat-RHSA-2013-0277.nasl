#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0277. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64750);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3411");
  script_bugtraq_id(54353);
  script_xref(name:"RHSA", value:"2013:0277");

  script_name(english:"RHEL 6 : dnsmasq (RHSA-2013:0277)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dnsmasq packages that fix one security issue, one bug, and add
various enhancements are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The dnsmasq packages contain Dnsmasq, a lightweight DNS (Domain Name
Server) forwarder and DHCP (Dynamic Host Configuration Protocol)
server.

It was discovered that dnsmasq, when used in combination with certain
libvirtd configurations, could incorrectly process network packets
from network interfaces that were intended to be prohibited. A remote,
unauthenticated attacker could exploit this flaw to cause a denial of
service via DNS amplification attacks. (CVE-2012-3411)

In order to fully address this issue, libvirt package users are
advised to install updated libvirt packages. Refer to RHSA-2013:0276
for additional information.

This update also fixes the following bug :

* Due to a regression, the lease change script was disabled.
Consequently, the 'dhcp-script' option in the /etc/dnsmasq.conf
configuration file did not work. This update corrects the problem and
the 'dhcp-script' option now works as expected. (BZ#815819)

This update also adds the following enhancements :

* Prior to this update, dnsmasq did not validate that the tftp
directory given actually existed and was a directory. Consequently,
configuration errors were not immediately reported on startup. This
update improves the code to validate the tftp root directory option.
As a result, fault finding is simplified especially when dnsmasq is
called by external processes such as libvirt. (BZ#824214)

* The dnsmasq init script used an incorrect Process Identifier (PID)
in the 'stop', 'restart', and 'condrestart' commands. Consequently, if
there were some dnsmasq instances running besides the system one
started by the init script, then repeated calling of 'service dnsmasq'
with 'stop' or 'restart' would kill all running dnsmasq instances,
including ones not started with the init script. The dnsmasq init
script code has been corrected to obtain the correct PID when calling
the 'stop', 'restart', and 'condrestart' commands. As a result, if
there are dnsmasq instances running in addition to the system one
started by the init script, then by calling 'service dnsmasq' with
'stop' or 'restart' only the system one is stopped or restarted.
(BZ#850944)

* When two or more dnsmasq processes were running with DHCP enabled on
one interface, DHCP RELEASE packets were sometimes lost. Consequently,
when two or more dnsmasq processes were running with DHCP enabled on
one interface, releasing IP addresses sometimes failed. This update
sets the SO_BINDTODEVICE socket option on DHCP sockets if running
dnsmasq with DHCP enabled on one interface. As a result, when two or
more dnsmasq processes are running with DHCP enabled on one interface,
they can release IP addresses as expected. (BZ#887156)

All users of dnsmasq are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  # https://rhn.redhat.com/errata/RHSA-2013-0276.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2013:0277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3411"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected dnsmasq, dnsmasq-debuginfo and / or dnsmasq-utils
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2013:0277";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dnsmasq-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dnsmasq-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dnsmasq-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dnsmasq-debuginfo-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dnsmasq-debuginfo-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dnsmasq-debuginfo-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dnsmasq-utils-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dnsmasq-utils-2.48-13.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dnsmasq-utils-2.48-13.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq / dnsmasq-debuginfo / dnsmasq-utils");
  }
}
