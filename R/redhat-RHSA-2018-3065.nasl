#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3065. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118522);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id(
    "CVE-2018-5800",
    "CVE-2018-5801",
    "CVE-2018-5802",
    "CVE-2018-5805",
    "CVE-2018-5806"
  );
  script_xref(name:"RHSA", value:"2018:3065");

  script_name(english:"RHEL 7 : libkdcraw (RHSA-2018:3065)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for libkdcraw is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Libkdcraw is a C++ interface around the LibRaw library used to decode
the RAW picture files.

Security Fix(es) :

* LibRaw: Stack-based buffer overflow in quicktake_100_load_raw()
function in internal/dcraw_common.cpp (CVE-2018-5805)

* LibRaw: Heap-based buffer overflow in LibRaw::kodak_ycbcr_load_raw
function in internal/dcraw_common.cpp (CVE-2018-5800)

* LibRaw: NULL pointer dereference in LibRaw::unpack function src/
libraw_cxx.cpp (CVE-2018-5801)

* LibRaw: Out-of-bounds read in kodak_radc_load_raw function internal/
dcraw_common.cpp (CVE-2018-5802)

* LibRaw: NULL pointer dereference in leaf_hdr_load_raw() function in
internal/dcraw_common.cpp (CVE-2018-5806)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3395ff0b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3065");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5800");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5801");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5802");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5806");
  script_set_attribute(attribute:"solution", value:
"Update the affected libkdcraw, libkdcraw-debuginfo and / or
libkdcraw-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libkdcraw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libkdcraw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libkdcraw-devel");
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
  rhsa = "RHSA-2018:3065";
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
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libkdcraw-4.10.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libkdcraw-4.10.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libkdcraw-debuginfo-4.10.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libkdcraw-debuginfo-4.10.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libkdcraw-devel-4.10.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libkdcraw-devel-4.10.5-5.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libkdcraw / libkdcraw-debuginfo / libkdcraw-devel");
  }
}
