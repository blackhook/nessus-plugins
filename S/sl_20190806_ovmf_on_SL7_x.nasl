#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128248);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2017-5731", "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734", "CVE-2017-5735", "CVE-2018-12181", "CVE-2018-3613", "CVE-2018-5407", "CVE-2019-0160", "CVE-2019-0161");

  script_name(english:"Scientific Linux Security Update : ovmf on SL7.x x86_64 (20190806)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - edk2: Privilege escalation via processing of malformed
    files in TianoCompress.c (CVE-2017-5731)

  - edk2: Privilege escalation via processing of malformed
    files in BaseUefiDecompressLib.c (CVE-2017-5732)

  - edk2: Privilege escalation via heap-based buffer
    overflow in MakeTable() function (CVE-2017-5733)

  - edk2: Privilege escalation via stack-based buffer
    overflow in MakeTable() function (CVE-2017-5734)

  - edk2: Privilege escalation via heap-based buffer
    overflow in Decode() function (CVE-2017-5735)

  - edk2: Logic error in MdeModulePkg in EDK II firmware
    allows for privilege escalation by authenticated users
    (CVE-2018-3613)

  - openssl: Side-channel vulnerability on
    SMT/Hyper-Threading architectures (PortSmash)
    (CVE-2018-5407)

  - edk2: Stack buffer overflow with corrupted BMP
    (CVE-2018-12181)

  - edk2: buffer overflows in PartitionDxe and UdfDxe with
    long file names and invalid UDF media (CVE-2019-0160)

  - edk2: stack overflow in XHCI causing denial of service
    (CVE-2019-0161)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=32556
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a96187f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected OVMF package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:OVMF");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"OVMF-20180508-6.gitee3198e672e2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF");
}
