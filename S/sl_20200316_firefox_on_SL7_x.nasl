#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(134647);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2019-20503", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6814");

  script_name(english:"Scientific Linux Security Update : firefox on SL7.x x86_64 (20200316)");
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
"This update upgrades Firefox to version 68.6.0 ESR.

Security Fix(es) :

  - Mozilla: Use-after-free when removing data about origins
    (CVE-2020-6805)

  - Mozilla: BodyStream::OnInputStreamReady was missing
    protections against state confusion (CVE-2020-6806)

  - Mozilla: Use-after-free in cubeb during stream
    destruction (CVE-2020-6807)

  - Mozilla: Memory safety bugs fixed in Firefox 74 and
    Firefox ESR 68.6 (CVE-2020-6814)

  - Mozilla: Out of bounds reads in
    sctp_load_addresses_from_init (CVE-2019-20503)

  - Mozilla: Devtools' 'Copy as cURL' feature did not fully
    escape website- controlled data, potentially leading to
    command injection (CVE-2020-6811)

  - Mozilla: The names of AirPods with personally
    identifiable information were exposed to websites with
    camera or microphone permission (CVE-2020-6812)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2003&L=SCIENTIFIC-LINUX-ERRATA&P=2638
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?014c1e32"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6814");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-68.6.0-1.el7_7", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-debuginfo-68.6.0-1.el7_7", allowmaj:TRUE)) flag++;


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
