#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(125447);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-18511", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Scientific Linux Security Update : firefox on SL6.x i386/x86_64 (20190523)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Security Fix(es) :

  - Mozilla: Memory safety bugs fixed in Firefox 67 and
    Firefox ESR 60.7 (CVE-2019-9800)

  - Mozilla: Cross-origin theft of images with
    createImageBitmap (CVE-2019-9797)

  - Mozilla: Type confusion with object groups and
    UnboxedObjects (CVE-2019-9816)

  - Mozilla: Stealing of cross-domain images using canvas
    (CVE-2019-9817)

  - Mozilla: Compartment mismatch with fetch API
    (CVE-2019-9819)

  - Mozilla: Use-after-free of ChromeEventHandler by
    DocShell (CVE-2019-9820)

  - Mozilla: Use-after-free in XMLHttpRequest
    (CVE-2019-11691)

  - Mozilla: Use-after-free removing listeners in the event
    listener manager (CVE-2019-11692)

  - Mozilla: Buffer overflow in WebGL bufferdata on Linux
    (CVE-2019-11693)

  - mozilla: Cross-origin theft of images with
    ImageBitmapRenderingContext (CVE-2018-18511)

  - chromium-browser: Out of bounds read in Skia
    (CVE-2019-5798)

  - Mozilla: Theft of user history data through drag and
    drop of hyperlinks to and from bookmarks
    (CVE-2019-11698)

  - libpng: use-after-free in png_image_free in png.c
    (CVE-2019-7317)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1905&L=SCIENTIFIC-LINUX-ERRATA&P=6485
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c08fdc1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"firefox-60.7.0-1.el6_10", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-60.7.0-1.el6_10", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
