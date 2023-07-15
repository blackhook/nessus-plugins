#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(110121);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5159", "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5185");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL6.x i386/x86_64 (20180524)");
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
"This update upgrades Thunderbird to version 52.8.0.

Security Fix(es) :

  - Mozilla: Memory safety bugs fixed in Firefox 60 and
    Firefox ESR 52.8 (CVE-2018-5150)

  - Mozilla: Backport critical security fixes in Skia
    (CVE-2018-5183)

  - Mozilla: Use-after-free with SVG animations and clip
    paths (CVE-2018-5154)

  - Mozilla: Use-after-free with SVG animations and text
    paths (CVE-2018-5155)

  - Mozilla: Integer overflow and out-of-bounds write in
    Skia (CVE-2018-5159)

  - Mozilla: Full plaintext recovery in S/MIME via
    chosen-ciphertext attack (CVE-2018-5184)

  - Mozilla: Hang via malformed headers (CVE-2018-5161)

  - Mozilla: Encrypted mail leaks plaintext through src
    attribute (CVE-2018-5162)

  - Mozilla: Lightweight themes can be installed without
    user interaction (CVE-2018-5168)

  - Mozilla: Filename spoofing for external attachments
    (CVE-2018-5170)

  - Mozilla: Buffer overflow during UTF-8 to Unicode string
    conversion through legacy extension (CVE-2018-5178)

  - Mozilla: Leaking plaintext through HTML forms
    (CVE-2018-5185)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1805&L=scientific-linux-errata&F=&S=&P=26996
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0690ee69"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/25");
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
if (rpm_check(release:"SL6", reference:"thunderbird-52.8.0-2.el6_9", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-52.8.0-2.el6_9", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
