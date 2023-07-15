#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149183);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2017-5503",
    "CVE-2017-5504",
    "CVE-2017-5505",
    "CVE-2021-26926",
    "CVE-2021-3443",
    "CVE-2021-3467"
  );

  script_name(english:"EulerOS 2.0 SP3 : jasper (EulerOS-SA-2021-1804)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the jasper package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in jasper before 2.0.25. An out of
    bounds read issue was found in jp2_decode function whic
    may lead to disclosure of information or program
    crash.(CVE-2021-26926)

  - A NULL pointer dereference flaw was found in the way
    Jasper versions before 2.0.26 handled component
    references in CDEF box in the JP2 image format decoder.
    A specially crafted JP2 image file could cause an
    application using the Jasper library to crash when
    opened.(CVE-2021-3467)

  - A NULL pointer dereference flaw was found in the way
    Jasper versions before 2.0.27 handled component
    references in the JP2 image format decoder. A specially
    crafted JP2 image file could cause an application using
    the Jasper library to crash when opened.(CVE-2021-3443)

  - The dec_clnpass function in libjasper/jpc/jpc_t1dec.c
    in JasPer 1.900.27 allows remote attackers to cause a
    denial of service (invalid memory write and crash) or
    possibly have unspecified other impact via a crafted
    image.(CVE-2017-5503)

  - The jas_matrix_asl function in jas_seq.c in JasPer
    1.900.27 allows remote attackers to cause a denial of
    service (invalid memory read and crash) via a crafted
    image.(CVE-2017-5505)

  - The jpc_undo_roi function in libjasper/jpc/jpc_dec.c in
    JasPer 1.900.27 allows remote attackers to cause a
    denial of service (invalid memory read and crash) via a
    crafted image.(CVE-2017-5504)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1804
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33051eb");
  script_set_attribute(attribute:"solution", value:
"Update the affected jasper packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["jasper-libs-1.900.1-33.h11"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper");
}
