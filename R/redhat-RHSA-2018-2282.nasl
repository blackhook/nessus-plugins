#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2282. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111487);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-16064", "CVE-2018-4117", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");
  script_xref(name:"RHSA", value:"2018:2282");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2018:2282)");
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

This update upgrades Chromium to version 68.0.3440.75.

Security Fix(es) :

* chromium-browser: Stack buffer overflow in Skia (CVE-2018-6153)

* chromium-browser: Heap buffer overflow in WebGL (CVE-2018-6154)

* chromium-browser: Use after free in WebRTC (CVE-2018-6155)

* chromium-browser: Heap buffer overflow in WebRTC (CVE-2018-6156)

* chromium-browser: Type confusion in WebRTC (CVE-2018-6157)

* chromium-browser: Cross origin information disclosure in Service
Workers (CVE-2018-6150)

* chromium-browser: Bad cast in DevTools (CVE-2018-6151)

* chromium-browser: Local file write in DevTools (CVE-2018-6152)

* chromium-browser: Use after free in Blink (CVE-2018-6158)

* chromium-browser: Same origin policy bypass in ServiceWorker
(CVE-2018-6159)

* chromium-browser: Same origin policy bypass in WebAudio
(CVE-2018-6161)

* chromium-browser: Heap buffer overflow in WebGL (CVE-2018-6162)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6163)

* chromium-browser: Same origin policy bypass in ServiceWorker
(CVE-2018-6164)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6165)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6166)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6167)

* chromium-browser: CORS bypass in Blink (CVE-2018-6168)

* chromium-browser: Permissions bypass in extension installation
(CVE-2018-6169)

* chromium-browser: Type confusion in PDFium (CVE-2018-6170)

* chromium-browser: Use after free in WebBluetooth (CVE-2018-6171)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6172)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6173)

* chromium-browser: Integer overflow in SwiftShader (CVE-2018-6174)

* chromium-browser: URL spoof in Omnibox (CVE-2018-6175)

* chromium-browser: Local user privilege escalation in Extensions
(CVE-2018-6176)

* chromium-browser: Cross origin information leak in Blink
(CVE-2018-4117)

* chromium-browser: Request privilege escalation in Extensions
(CVE-2018-6044)

* chromium-browser: Cross origin information leak in Blink
(CVE-2018-6177)

* chromium-browser: UI spoof in Extensions (CVE-2018-6178)

* chromium-browser: Local file information leak in Extensions
(CVE-2018-6179)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-4117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-6179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-16064"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
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
  rhsa = "RHSA-2018:2282";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-68.0.3440.75-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-68.0.3440.75-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-68.0.3440.75-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-68.0.3440.75-1.el6_10", allowmaj:TRUE)) flag++;

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
