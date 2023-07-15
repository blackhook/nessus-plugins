#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128245);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16426", "CVE-2018-16427");

  script_name(english:"Scientific Linux Security Update : opensc on SL7.x x86_64 (20190806)");
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
"The following packages have been upgraded to a later upstream version:
opensc (0.19.0).

Security Fix(es) :

  - opensc: Buffer overflows handling responses from Muscle
    Cards in card- muscle.c:muscle_list_files()
    (CVE-2018-16391)

  - opensc: Buffer overflows handling responses from TCOS
    Cards in card- tcos.c:tcos_select_file()
    (CVE-2018-16392)

  - opensc: Buffer overflows handling responses from Gemsafe
    V1 Smartcards in
    pkcs15-gemsafeV1.c:gemsafe_get_cert_len()
    (CVE-2018-16393)

  - opensc: Buffer overflow handling string concatention in
    tools/util.c:util_acl_to_str() (CVE-2018-16418)

  - opensc: Buffer overflow handling responses from
    Cryptoflex cards in cryptoflex-tool.c:read_public_key()
    (CVE-2018-16419)

  - opensc: Buffer overflows handling responses from ePass
    2003 Cards in card-epass2003.c:decrypt_response()
    (CVE-2018-16420)

  - opensc: Buffer overflows handling responses from CAC
    Cards in card- cac.c:cac_get_serial_nr_from_CUID()
    (CVE-2018-16421)

  - opensc: Buffer overflow handling responses from esteid
    cards in pkcs15-esteid.c:sc_pkcs15emu_esteid_init()
    (CVE-2018-16422)

  - opensc: Double free handling responses from smartcards
    in libopensc/sc.c:sc_file_set_sec_attr()
    (CVE-2018-16423)

  - opensc: Out of bounds reads handling responses from
    smartcards (CVE-2018-16427)

  - opensc: Infinite recusrion handling responses from
    IAS-ECC cards in card-iasecc.c:iasecc_select_file()
    (CVE-2018-16426)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=34077
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?690bc3a0"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected opensc and / or opensc-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16423");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:opensc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"opensc-0.19.0-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"opensc-debuginfo-0.19.0-3.el7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc / opensc-debuginfo");
}
