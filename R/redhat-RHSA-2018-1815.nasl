#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1815. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110406);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6129", "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134", "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147");
  script_xref(name:"RHSA", value:"2018:1815");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2018:1815)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for chromium-browser is now available for Red Hat Enterprise
Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Chromium is an open source web browser, powered by WebKit (Blink).

This update upgrades Chromium to version 67.0.3396.62.

Security Fix(es) :

* chromium-browser: Use after free in Blink (CVE-2018-6123)

* chromium-browser: Type confusion in Blink (CVE-2018-6124)

* chromium-browser: Overly permissive policy in WebUSB (CVE-2018-6125)

* chromium-browser: Heap buffer overflow in Skia (CVE-2018-6126)

* chromium-browser: Use after free in indexedDB (CVE-2018-6127)

* chromium-browser: Out of bounds memory access in WebRTC
(CVE-2018-6129)

* chromium-browser: Out of bounds memory access in WebRTC
(CVE-2018-6130)

* chromium-browser: Incorrect mutability protection in WebAssembly
(CVE-2018-6131)

* chromium-browser: Use of uninitialized memory in WebRTC
(CVE-2018-6132)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6133)

* chromium-browser: Referrer Policy bypass in Blink (CVE-2018-6134)

* chromium-browser: UI spoofing in Blink (CVE-2018-6135)

* chromium-browser: Out of bounds memory access in V8 (CVE-2018-6136)

* chromium-browser: Leak of visited status of page in Blink
(CVE-2018-6137)

* chromium-browser: Overly permissive policy in Extensions
(CVE-2018-6138)

* chromium-browser: Restrictions bypass in the debugger extension API
(CVE-2018-6139)

* chromium-browser: Restrictions bypass in the debugger extension API
(CVE-2018-6140)

* chromium-browser: Heap buffer overflow in Skia (CVE-2018-6141)

* chromium-browser: Out of bounds memory access in V8 (CVE-2018-6142)

* chromium-browser: Out of bounds memory access in V8 (CVE-2018-6143)

* chromium-browser: Out of bounds memory access in PDFium
(CVE-2018-6144)

* chromium-browser: Incorrect escaping of MathML in Blink
(CVE-2018-6145)

* chromium-browser: Password fields not taking advantage of OS
protections in Views (CVE-2018-6147)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6132"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6147"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:1815";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-67.0.3396.62-2.el6_9", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-67.0.3396.62-2.el6_9", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-67.0.3396.62-2.el6_9", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-67.0.3396.62-2.el6_9", allowmaj:TRUE)) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium-browser / chromium-browser-debuginfo");
  }
}
