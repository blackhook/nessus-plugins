#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(126435);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11703", "CVE-2019-11704", "CVE-2019-11705", "CVE-2019-11706", "CVE-2019-11707", "CVE-2019-11708");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2019-0458");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL7.x x86_64 (20190627)");
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

  - Mozilla: Type confusion in Array.pop (CVE-2019-11707)

  - thunderbird: Stack buffer overflow in
    icalrecur_add_bydayrules in icalrecur.c (CVE-2019-11705)

  - Mozilla: Sandbox escape using Prompt:Open
    (CVE-2019-11708)

  - thunderbird: Heap buffer over read in icalparser.c
    parser_get_next_char (CVE-2019-11703)

  - thunderbird: Heap buffer overflow in
    icalmemory_strdup_and_dequote function in icalvalue.c
    (CVE-2019-11704)

  - thunderbird: Type confusion in
    icaltimezone_get_vtimezone_properties function in
    icalproperty.c (CVE-2019-11706)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1907&L=SCIENTIFIC-LINUX-ERRATA&P=385
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2319d5de"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11708");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"thunderbird-60.7.2-2.el7_6", allowmaj:TRUE)) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"thunderbird-debuginfo-60.7.2-2.el7_6", allowmaj:TRUE)) flag++;


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
