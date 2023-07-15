#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3803. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119568);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-17480",
    "CVE-2018-17481",
    "CVE-2018-18335",
    "CVE-2018-18336",
    "CVE-2018-18337",
    "CVE-2018-18338",
    "CVE-2018-18339",
    "CVE-2018-18340",
    "CVE-2018-18341",
    "CVE-2018-18342",
    "CVE-2018-18343",
    "CVE-2018-18344",
    "CVE-2018-18345",
    "CVE-2018-18346",
    "CVE-2018-18347",
    "CVE-2018-18348",
    "CVE-2018-18349",
    "CVE-2018-18350",
    "CVE-2018-18351",
    "CVE-2018-18352",
    "CVE-2018-18353",
    "CVE-2018-18354",
    "CVE-2018-18355",
    "CVE-2018-18356",
    "CVE-2018-18357",
    "CVE-2018-18358",
    "CVE-2018-18359"
  );
  script_xref(name:"RHSA", value:"2018:3803");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2018:3803)");

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

This update upgrades Chromium to version 71.0.3578.80.

Security Fix(es) :

* chromium-browser: Out of bounds write in V8 (CVE-2018-17480)

* chromium-browser: Use after frees in PDFium (CVE-2018-17481)

* chromium-browser: Heap buffer overflow in Skia (CVE-2018-18335)

* chromium-browser: Use after free in PDFium (CVE-2018-18336)

* chromium-browser: Use after free in Blink (CVE-2018-18337)

* chromium-browser: Heap buffer overflow in Canvas (CVE-2018-18338)

* chromium-browser: Use after free in WebAudio (CVE-2018-18339)

* chromium-browser: Use after free in MediaRecorder (CVE-2018-18340)

* chromium-browser: Heap buffer overflow in Blink (CVE-2018-18341)

* chromium-browser: Out of bounds write in V8 (CVE-2018-18342)

* chromium-browser: Use after free in Skia (CVE-2018-18343)

* chromium-browser: Inappropriate implementation in Extensions
(CVE-2018-18344)

* chromium-browser: Inappropriate implementation in Site Isolation
(CVE-2018-18345)

* chromium-browser: Incorrect security UI in Blink (CVE-2018-18346)

* chromium-browser: Inappropriate implementation in Navigation
(CVE-2018-18347)

* chromium-browser: Inappropriate implementation in Omnibox
(CVE-2018-18348)

* chromium-browser: Insufficient policy enforcement in Blink
(CVE-2018-18349)

* chromium-browser: Insufficient policy enforcement in Blink
(CVE-2018-18350)

* chromium-browser: Insufficient policy enforcement in Navigation
(CVE-2018-18351)

* chromium-browser: Inappropriate implementation in Media
(CVE-2018-18352)

* chromium-browser: Inappropriate implementation in Network
Authentication (CVE-2018-18353)

* chromium-browser: Insufficient data validation in Shell Integration
(CVE-2018-18354)

* chromium-browser: Insufficient policy enforcement in URL Formatter
(CVE-2018-18355)

* chromium-browser: Use after free in Skia (CVE-2018-18356)

* chromium-browser: Insufficient policy enforcement in URL Formatter
(CVE-2018-18357)

* chromium-browser: Insufficient policy enforcement in Proxy
(CVE-2018-18358)

* chromium-browser: Out of bounds read in V8 (CVE-2018-18359)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3803");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-17480");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-17481");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18335");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18336");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18337");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18338");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18339");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18340");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18341");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18342");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18343");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18344");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18345");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18346");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18347");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18348");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18349");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18350");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18352");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18353");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18354");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18355");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18356");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18357");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18358");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-18359");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18359");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

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
  rhsa = "RHSA-2018:3803";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-71.0.3578.80-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-71.0.3578.80-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-71.0.3578.80-1.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-71.0.3578.80-1.el6_10", allowmaj:TRUE)) flag++;

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
