#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137951);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id(
    "CVE-2017-13728",
    "CVE-2017-13729",
    "CVE-2017-13730",
    "CVE-2017-13731",
    "CVE-2017-13732",
    "CVE-2017-13733",
    "CVE-2017-13734",
    "CVE-2019-17594",
    "CVE-2019-17595"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : ncurses (EulerOS-SA-2020-1732)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ncurses packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - There is a heap-based buffer over-read in the fmt_entry
    function in tinfo/comp_hash.c in the terminfo library
    in ncurses before 6.1-20191012.(CVE-2019-17595)

  - There is a heap-based buffer over-read in the
    _nc_find_entry function in tinfo/comp_hash.c in the
    terminfo library in ncurses before
    6.1-20191012.(CVE-2019-17594)

  - There is an illegal address access in the
    _nc_safe_strcat function in strings.c in ncurses 6.0
    that will lead to a remote denial of service
    attack.(CVE-2017-13734)

  - There is an illegal address access in the fmt_entry
    function in progs/dump_entry.c in ncurses 6.0 that
    might lead to a remote denial of service
    attack.(CVE-2017-13733)

  - There is an illegal address access in the function
    dump_uses() in progs/dump_entry.c in ncurses 6.0 that
    might lead to a remote denial of service
    attack.(CVE-2017-13732)

  - There is an illegal address access in the function
    postprocess_termcap() in parse_entry.c in ncurses 6.0
    that will lead to a remote denial of service
    attack.(CVE-2017-13731)

  - There is an illegal address access in the function
    _nc_read_entry_source() in progs/tic.c in ncurses 6.0
    that might lead to a remote denial of service
    attack.(CVE-2017-13730)

  - There is an illegal address access in the _nc_save_str
    function in alloc_entry.c in ncurses 6.0. It will lead
    to a remote denial of service attack.(CVE-2017-13729)

  - There is an infinite loop in the next_char function in
    comp_scan.c in ncurses 6.0, related to libtic. A
    crafted input will lead to a remote denial of service
    attack.(CVE-2017-13728)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1732
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb8657d5");
  script_set_attribute(attribute:"solution", value:
"Update the affected ncurses packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17595");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ncurses-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ncurses-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ncurses-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ncurses-5.9-14.20130511.h7.eulerosv2r7",
        "ncurses-base-5.9-14.20130511.h7.eulerosv2r7",
        "ncurses-devel-5.9-14.20130511.h7.eulerosv2r7",
        "ncurses-libs-5.9-14.20130511.h7.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ncurses");
}
