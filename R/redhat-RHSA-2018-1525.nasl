#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1525. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109910);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2017-12196", "CVE-2018-1073", "CVE-2018-1111", "CVE-2018-5968", "CVE-2018-7750", "CVE-2018-8088");
  script_xref(name:"RHSA", value:"2018:1525");

  script_name(english:"RHEL 7 : Virtualization (RHSA-2018:1525)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for rhvm-appliance is now available for Red Hat
Virtualization 4 for RHEL 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The RHV-M Virtual Appliance automates the process of installing and
configuring the Red Hat Virtualization Manager. The appliance is
available to download as an OVA file from the Customer Portal.

The following packages have been upgraded to a later upstream version:
rhvm-appliance (4.2). (BZ#1558801, BZ#1563545)

Security Fix(es) :

* python-paramiko: Authentication bypass in transport.py
(CVE-2018-7750)

* slf4j: Deserialisation vulnerability in EventData constructor can
allow for arbitrary code execution (CVE-2018-8088)

* undertow: Client can use bogus uri in Digest authentication
(CVE-2017-12196)

* jackson-databind: unsafe deserialization due to incomplete blacklist
(incomplete fix for CVE-2017-7525 and CVE-2017-17485) (CVE-2018-5968)

* ovirt-engine: account enumeration through login to web console
(CVE-2018-1073)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Chris McCown for reporting CVE-2018-8088.
The CVE-2017-12196 issue was discovered by Jan Stourac (Red Hat).

Enhancement(s) :

* Previously, the default memory allotment for the RHV-M Virtual
Appliance was always large enough to include support for user
additions.

In this release, the RHV-M Virtual Appliance includes a swap partition
that enables the memory to be increased when required. (BZ#1422982)

* Previously, the partitioning scheme for the RHV-M Virtual Appliance
included two primary partitions, '/' and swap.

In this release, the disk partitioning scheme has been modified to
match the scheme specified by NIST. The updated disk partitions are as
follows :

/boot 1G (primary) /home 1G (lvm) /tmp 2G (lvm) /var 20G (lvm)
/var/log 10G (lvm) /var/log/audit 1G (lvm) swap 8G (lvm) / 6G
(primary) (BZ#1463853)

* Previously, the version tag was used as part of the RPM's naming
scheme, for example, '4.1.timestamp', which created differences
between the upstream and downstream versioning schemes. In this
release, the downstream versioning scheme is aligned with the upstream
scheme and the timestamp has moved from the version tag to the release
tag. (BZ#1464486)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-7750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-8088"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhvm-appliance package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DHCP Client Command Injection (DynoRoot)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm-appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");
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
  rhsa = "RHSA-2018:1525";
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

  if (rpm_check(release:"RHEL7", reference:"rhvm-appliance-4.2-20180504.0.el7")) flag++;

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
