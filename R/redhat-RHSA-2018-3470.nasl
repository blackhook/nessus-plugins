#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3470. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118790);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id(
    "CVE-2018-10858",
    "CVE-2018-10873",
    "CVE-2018-10904",
    "CVE-2018-10907",
    "CVE-2018-10911",
    "CVE-2018-10913",
    "CVE-2018-10914",
    "CVE-2018-10923",
    "CVE-2018-10926",
    "CVE-2018-10927",
    "CVE-2018-10928",
    "CVE-2018-10929",
    "CVE-2018-10930",
    "CVE-2018-14652",
    "CVE-2018-14653",
    "CVE-2018-14654",
    "CVE-2018-14659",
    "CVE-2018-14660",
    "CVE-2018-14661",
    "CVE-2018-1000805"
  );
  script_xref(name:"RHSA", value:"2018:3470");

  script_name(english:"RHEL 7 : Virtualization Manager (RHSA-2018:3470)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for imgbased, redhat-release-virtualization-host, and
redhat-virtualization-host is now available for Red Hat Virtualization
4 for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The redhat-virtualization-host packages provide the Red Hat
Virtualization Host. These packages include
redhat-release-virtualization-host, ovirt-node, and rhev-hypervisor.
Red Hat Virtualization Hosts (RHVH) are installed using a special
build of Red Hat Enterprise Linux with only the packages required to
host virtual machines. RHVH features a Cockpit user interface for
monitoring the host's resources and performing administrative tasks.

Security Fix(es) :

* spice: Missing check in demarshal.py:write_validate_array_item()
allows for buffer overflow and denial of service (CVE-2018-10873)

* glusterfs: Multiple flaws (CVE-2018-10904, CVE-2018-10907,
CVE-2018-10923, CVE-2018-10926, CVE-2018-10927, CVE-2018-10928,
CVE-2018-10929, CVE-2018-10930, CVE-2018-10911, CVE-2018-10914,
CVE-2018-14652, CVE-2018-14653, CVE-2018-14654, CVE-2018-14659,
CVE-2018-14660, CVE-2018-14661, CVE-2018-10913)

* samba: Insufficient input validation in libsmbclient
(CVE-2018-10858)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Michael Hanselmann (hansmi.ch) for
reporting CVE-2018-10904, CVE-2018-10907, CVE-2018-10923,
CVE-2018-10926, CVE-2018-10927, CVE-2018-10928, CVE-2018-10929,
CVE-2018-10930, CVE-2018-10911, CVE-2018-10914, CVE-2018-14652,
CVE-2018-14653, CVE-2018-14654, CVE-2018-14659, CVE-2018-14660,
CVE-2018-14661, and CVE-2018-10913. The CVE-2018-10873 issue was
discovered by Frediano Ziglio (Red Hat).

Bug Fix(es) :

* When upgrading Red Hat Virtualization Host (RHVH), imgbased fails to
run garbage collection on previous layers, so new logical volumes are
removed, and the boot entry points to a logical volume that was
removed.

If the RHVH upgrade finishes successfully, the hypervisor boots
successfully, even if garbage collection fails. (BZ#1632058)

* During the upgrade process, when lvremove runs garbage collection,
it prompts for user confirmation, causing the upgrade process to fail.
Now the process uses 'lvremove --force' when trying to remove logical
volumes and does not fail even if garbage collection fails, and as a
result, the upgrade process finishes successfully. (BZ#1632585)");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3470");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10858");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10873");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10904");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10907");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10911");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10913");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10914");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10923");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10926");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10927");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10928");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10929");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-10930");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14652");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14653");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1000805");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14654");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:imgbased");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-imgbased");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-virtualization-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update-placeholder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2018:3470";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"redhat-release-virtualization-host-4.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Red Hat Virtualization 4");

  if (rpm_check(release:"RHEL7", reference:"imgbased-1.0.29-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-imgbased-1.0.29-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"redhat-release-virtualization-host-4.2-7.3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-virtualization-host-image-update-4.2-20181026.0.el7_6")) flag++;
  if (rpm_check(release:"RHEL7", reference:"redhat-virtualization-host-image-update-placeholder-4.2-7.3.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imgbased / python-imgbased / redhat-release-virtualization-host / etc");
  }
}
