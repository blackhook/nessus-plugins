#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1267 and 
# CentOS Errata and Security Advisory 2019:1267 respectively.
#

include('compat.inc');

if (description)
{
  script_id(125554);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-18511",
    "CVE-2019-11691",
    "CVE-2019-11692",
    "CVE-2019-11693",
    "CVE-2019-11698",
    "CVE-2019-5798",
    "CVE-2019-7317",
    "CVE-2019-9797",
    "CVE-2019-9800",
    "CVE-2019-9816",
    "CVE-2019-9817",
    "CVE-2019-9819",
    "CVE-2019-9820"
  );
  script_xref(name:"RHSA", value:"2019:1267");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 6 : firefox (CESA-2019:1267)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for firefox is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.7.0 ESR.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 67 and Firefox ESR 60.7
(CVE-2019-9800)

* Mozilla: Cross-origin theft of images with createImageBitmap
(CVE-2019-9797)

* Mozilla: Type confusion with object groups and UnboxedObjects
(CVE-2019-9816)

* Mozilla: Stealing of cross-domain images using canvas
(CVE-2019-9817)

* Mozilla: Compartment mismatch with fetch API (CVE-2019-9819)

* Mozilla: Use-after-free of ChromeEventHandler by DocShell
(CVE-2019-9820)

* Mozilla: Use-after-free in XMLHttpRequest (CVE-2019-11691)

* Mozilla: Use-after-free removing listeners in the event listener
manager (CVE-2019-11692)

* Mozilla: Buffer overflow in WebGL bufferdata on Linux
(CVE-2019-11693)

* mozilla: Cross-origin theft of images with
ImageBitmapRenderingContext (CVE-2018-18511)

* chromium-browser: Out of bounds read in Skia (CVE-2019-5798)

* Mozilla: Theft of user history data through drag and drop of
hyperlinks to and from bookmarks (CVE-2019-11698)

* libpng: use-after-free in png_image_free in png.c (CVE-2019-7317)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  # https://lists.centos.org/pipermail/centos-announce/2019-May/023318.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1244372e");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11691");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"firefox-60.7.0-1.el6.centos", allowmaj:TRUE)) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
