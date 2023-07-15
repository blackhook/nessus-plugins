#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2402. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112026);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390");
  script_xref(name:"RHSA", value:"2018:2402");

  script_name(english:"RHEL 7 : Virtualization (RHSA-2018:2402) (Foreshadow)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for rhvm-appliance is now available for Red Hat
Virtualization 4 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The RHV-M Virtual Appliance automates the process of installing and
configuring the Red Hat Virtualization Manager. The appliance is
available to download as an OVA file from the Customer Portal.

Security Fix(es) :

* Modern operating systems implement virtualization of physical memory
to efficiently use available system resources and provide inter-domain
protection through access control and isolation. The L1TF issue was
found in the way the x86 microprocessor designs have implemented
speculative execution of instructions (a commonly used performance
optimisation) in combination with handling of page-faults caused by
terminated virtual to physical address resolving process. As a result,
an unprivileged attacker could use this flaw to read privileged memory
of the kernel or other processes and/or cross guest/host boundaries to
read host memory by conducting targeted cache side-channel attacks.
(CVE-2018-3620, CVE-2018-3646)

* A flaw named SegmentSmack was found in the way the Linux kernel
handled specially crafted TCP packets. A remote attacker could use
this flaw to trigger time and calculation expensive calls to
tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() functions by
sending specially modified packets within ongoing TCP sessions which
could lead to a CPU saturation and hence a denial of service on the
system. Maintaining the denial of service condition requires
continuous two-way TCP sessions to a reachable open port, thus the
attacks cannot be performed using spoofed IP addresses.
(CVE-2018-5390)

Red Hat would like to thank Intel OSSIRT (Intel.com) for reporting
CVE-2018-3620 and CVE-2018-3646 and Juha-Matti Tilli (Aalto
University, Department of Communications and Networking and Nokia Bell
Labs) for reporting CVE-2018-5390."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/L1TF"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5390"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhvm-appliance package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm-appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
  rhsa = "RHSA-2018:2402";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"rhvm-appliance-4.2-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Virtualization");

  if (rpm_check(release:"RHEL7", reference:"rhvm-appliance-4.2-20180813.0.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhvm-appliance");
  }
}
