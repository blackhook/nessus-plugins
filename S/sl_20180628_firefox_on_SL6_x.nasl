#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(110971);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2017-7762", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-5156", "CVE-2018-5188", "CVE-2018-6126");

  script_name(english:"Scientific Linux Security Update : firefox on SL6.x i386/x86_64 (20180628)");
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
"This update upgrades Firefox to version 60.1.0 ESR.

Many older firefox extensions must be updated to work with this new
release.

Security Fix(es) :

  - Mozilla: Memory safety bugs fixed in Firefox 61, Firefox
    ESR 60.1, and Firefox ESR 52.9 (CVE-2018-5188)

  - Mozilla: Buffer overflow using computed size of canvas
    element (CVE-2018-12359)

  - Mozilla: Use-after-free using focus() (CVE-2018-12360)

  - Mozilla: Media recorder segmentation fault when track
    type is changed during capture (CVE-2018-5156)

  - Skia: Heap buffer overflow rasterizing paths in SVG
    (CVE-2018-6126)

  - Mozilla: Integer overflow in SSSE3 scaler
    (CVE-2018-12362)

  - Mozilla: Use-after-free when appending DOM nodes
    (CVE-2018-12363)

  - Mozilla: CSRF attacks through 307 redirects and NPAPI
    plugins (CVE-2018-12364)

  - Mozilla: address bar username and password spoofing in
    reader mode (CVE-2017-7762)

  - Mozilla: Compromised IPC child process can list local
    filenames (CVE-2018-12365)

  - Mozilla: Invalid data handling during QCMS
    transformations (CVE-2018-12366)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1807&L=scientific-linux-errata&F=&S=&P=3912
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5eea8cd"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"firefox-60.1.0-5.el6", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-60.1.0-5.el6", allowmaj:TRUE)) flag++;


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
