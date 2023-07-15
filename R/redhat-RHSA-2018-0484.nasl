#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0484. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108275);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-6057",
    "CVE-2018-6060",
    "CVE-2018-6061",
    "CVE-2018-6062",
    "CVE-2018-6063",
    "CVE-2018-6064",
    "CVE-2018-6065",
    "CVE-2018-6066",
    "CVE-2018-6067",
    "CVE-2018-6069",
    "CVE-2018-6070",
    "CVE-2018-6071",
    "CVE-2018-6072",
    "CVE-2018-6073",
    "CVE-2018-6074",
    "CVE-2018-6075",
    "CVE-2018-6076",
    "CVE-2018-6077",
    "CVE-2018-6078",
    "CVE-2018-6079",
    "CVE-2018-6080",
    "CVE-2018-6081",
    "CVE-2018-6082",
    "CVE-2018-6083"
  );
  script_xref(name:"RHSA", value:"2018:0484");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2018:0484)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for chromium-browser is now available for Red Hat Enterprise
Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Chromium is an open source web browser, powered by WebKit (Blink).

This update upgrades Chromium to version 65.0.3325.146.

Security Fix(es) :

* chromium-browser: incorrect permissions on shared memory
(CVE-2018-6057)

* chromium-browser: use-after-free in blink (CVE-2018-6060)

* chromium-browser: race condition in v8 (CVE-2018-6061)

* chromium-browser: heap buffer overflow in skia (CVE-2018-6062)

* chromium-browser: incorrect permissions on shared memory
(CVE-2018-6063)

* chromium-browser: type confusion in v8 (CVE-2018-6064)

* chromium-browser: integer overflow in v8 (CVE-2018-6065)

* chromium-browser: same origin bypass via canvas (CVE-2018-6066)

* chromium-browser: buffer overflow in skia (CVE-2018-6067)

* chromium-browser: stack-based buffer overflow in skia
(CVE-2018-6069)

* chromium-browser: csp bypass through extensions (CVE-2018-6070)

* chromium-browser: heap bufffer overflow in skia (CVE-2018-6071)

* chromium-browser: integer overflow in pdfium (CVE-2018-6072)

* chromium-browser: heap bufffer overflow in webgl (CVE-2018-6073)

* chromium-browser: mark-of-the-web bypass (CVE-2018-6074)

* chromium-browser: overly permissive cross origin downloads
(CVE-2018-6075)

* chromium-browser: incorrect handling of url fragment identifiers in
blink (CVE-2018-6076)

* chromium-browser: timing attack using svg filters (CVE-2018-6077)

* chromium-browser: url spoof in omnibox (CVE-2018-6078)

* chromium-browser: information disclosure via texture data in webgl
(CVE-2018-6079)

* chromium-browser: information disclosure in ipc call (CVE-2018-6080)

* chromium-browser: xss in interstitials (CVE-2018-6081)

* chromium-browser: circumvention of port blocking (CVE-2018-6082)

* chromium-browser: incorrect processing of appmanifests
(CVE-2018-6083)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0484");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6057");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6060");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6061");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6062");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6063");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6064");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6065");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6066");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6067");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6069");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6070");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6071");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6072");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6073");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6074");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6075");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6076");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6077");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6078");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6079");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6080");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6081");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6082");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-6083");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6083");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2018:0484";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-65.0.3325.146-2.el6_9", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-65.0.3325.146-2.el6_9", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-65.0.3325.146-2.el6_9", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-65.0.3325.146-2.el6_9", allowmaj:TRUE)) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium-browser / chromium-browser-debuginfo");
  }
}
