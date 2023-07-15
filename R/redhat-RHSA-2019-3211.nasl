#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3211. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130372);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-5870",
    "CVE-2019-5871",
    "CVE-2019-5872",
    "CVE-2019-5874",
    "CVE-2019-5875",
    "CVE-2019-5876",
    "CVE-2019-5877",
    "CVE-2019-5878",
    "CVE-2019-5879",
    "CVE-2019-5880",
    "CVE-2019-5881",
    "CVE-2019-13659",
    "CVE-2019-13660",
    "CVE-2019-13661",
    "CVE-2019-13662",
    "CVE-2019-13663",
    "CVE-2019-13664",
    "CVE-2019-13665",
    "CVE-2019-13666",
    "CVE-2019-13667",
    "CVE-2019-13668",
    "CVE-2019-13669",
    "CVE-2019-13670",
    "CVE-2019-13671",
    "CVE-2019-13673",
    "CVE-2019-13674",
    "CVE-2019-13675",
    "CVE-2019-13676",
    "CVE-2019-13677",
    "CVE-2019-13678",
    "CVE-2019-13679",
    "CVE-2019-13680",
    "CVE-2019-13681",
    "CVE-2019-13682",
    "CVE-2019-13683",
    "CVE-2019-13685",
    "CVE-2019-13686",
    "CVE-2019-13687",
    "CVE-2019-13688",
    "CVE-2019-13691",
    "CVE-2019-13692",
    "CVE-2019-13693",
    "CVE-2019-13694",
    "CVE-2019-13695",
    "CVE-2019-13696",
    "CVE-2019-13697"
  );
  script_xref(name:"RHSA", value:"2019:3211");

  script_name(english:"RHEL 6 : chromium-browser (RHSA-2019:3211)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for chromium-browser is now available for Red Hat Enterprise
Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Chromium is an open source web browser, powered by WebKit (Blink).

This update upgrades Chromium to version 77.0.3865.120.

Security Fix(es) :

* chromium-browser: Use-after-free in media (CVE-2019-5870)

* chromium-browser: Heap overflow in Skia (CVE-2019-5871)

* chromium-browser: Use-after-free in Mojo (CVE-2019-5872)

* chromium-browser: External URIs may trigger other browsers
(CVE-2019-5874)

* chromium-browser: URL bar spoof via download redirect
(CVE-2019-5875)

* chromium-browser: Use-after-free in media (CVE-2019-5876)

* chromium-browser: Out-of-bounds access in V8 (CVE-2019-5877)

* chromium-browser: Use-after-free in V8 (CVE-2019-5878)

* chromium-browser: Use-after-free in offline pages (CVE-2019-13686)

* chromium-browser: Use-after-free in media (CVE-2019-13688)

* chromium-browser: Omnibox spoof (CVE-2019-13691)

* chromium-browser: SOP bypass (CVE-2019-13692)

* chromium-browser: Use-after-free in IndexedDB (CVE-2019-13693)

* chromium-browser: Use-after-free in WebRTC (CVE-2019-13694)

* chromium-browser: Use-after-free in audio (CVE-2019-13695)

* chromium-browser: Use-after-free in V8 (CVE-2019-13696)

* chromium-browser: Cross-origin size leak (CVE-2019-13697)

* chromium-browser: Extensions can read some local files
(CVE-2019-5879)

* chromium-browser: SameSite cookie bypass (CVE-2019-5880)

* chromium-browser: Arbitrary read in SwiftShader (CVE-2019-5881)

* chromium-browser: URL spoof (CVE-2019-13659)

* chromium-browser: Full screen notification overlap (CVE-2019-13660)

* chromium-browser: Full screen notification spoof (CVE-2019-13661)

* chromium-browser: CSP bypass (CVE-2019-13662)

* chromium-browser: IDN spoof (CVE-2019-13663)

* chromium-browser: CSRF bypass (CVE-2019-13664)

* chromium-browser: Multiple file download protection bypass
(CVE-2019-13665)

* chromium-browser: Side channel using storage size estimate
(CVE-2019-13666)

* chromium-browser: URI bar spoof when using external app URIs
(CVE-2019-13667)

* chromium-browser: Global window leak via console (CVE-2019-13668)

* chromium-browser: HTTP authentication spoof (CVE-2019-13669)

* chromium-browser: V8 memory corruption in regex (CVE-2019-13670)

* chromium-browser: Dialog box fails to show origin (CVE-2019-13671)

* chromium-browser: Cross-origin information leak using devtools
(CVE-2019-13673)

* chromium-browser: IDN spoofing (CVE-2019-13674)

* chromium-browser: Extensions can be disabled by trailing slash
(CVE-2019-13675)

* chromium-browser: Google URI shown for certificate warning
(CVE-2019-13676)

* chromium-browser: Chrome web store origin needs to be isolated
(CVE-2019-13677)

* chromium-browser: Download dialog spoofing (CVE-2019-13678)

* chromium-browser: User gesture needed for printing (CVE-2019-13679)

* chromium-browser: IP address spoofing to servers (CVE-2019-13680)

* chromium-browser: Bypass on download restrictions (CVE-2019-13681)

* chromium-browser: Site isolation bypass (CVE-2019-13682)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3211");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5870");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5871");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5872");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5874");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5875");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5876");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5877");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5878");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5879");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5880");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-5881");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13662");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13664");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13665");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13667");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13668");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13670");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13671");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13673");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13674");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13675");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13676");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13677");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13678");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13679");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13680");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13681");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13682");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13683");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13685");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13686");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13687");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13688");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13691");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13692");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13693");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13694");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13695");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13696");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-13697");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser and / or
chromium-browser-debuginfo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5878");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:chromium-browser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2019:3211";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-77.0.3865.120-2.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-77.0.3865.120-2.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"chromium-browser-debuginfo-77.0.3865.120-2.el6_10", allowmaj:TRUE)) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"chromium-browser-debuginfo-77.0.3865.120-2.el6_10", allowmaj:TRUE)) flag++;

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
