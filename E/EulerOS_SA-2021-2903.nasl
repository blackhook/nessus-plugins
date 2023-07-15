#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156515);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/06");

  script_cve_id(
    "CVE-2020-35495",
    "CVE-2020-35496",
    "CVE-2020-35507",
    "CVE-2021-3487",
    "CVE-2021-3549"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.6 : binutils (EulerOS-SA-2021-2903)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - There's a flaw in binutils /bfd/pef.c. An attacker who is able to submit a crafted input file to be
    processed by the objdump program could cause a null pointer dereference. The greatest threat from this
    flaw is to application availability. This flaw affects binutils versions prior to 2.34. (CVE-2020-35495)

  - There's a flaw in bfd_pef_scan_start_address() of bfd/pef.c in binutils which could allow an attacker who
    is able to submit a crafted file to be processed by objdump to cause a NULL pointer dereference. The
    greatest threat of this flaw is to application availability. This flaw affects binutils versions prior to
    2.34. (CVE-2020-35496)

  - There's a flaw in bfd_pef_parse_function_stubs of bfd/pef.c in binutils in versions prior to 2.34 which
    could allow an attacker who is able to submit a crafted file to be processed by objdump to cause a NULL
    pointer dereference. The greatest threat of this flaw is to application availability. (CVE-2020-35507)

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

  - An out of bounds flaw was found in GNU binutils objdump utility version 2.36. An attacker could use this
    flaw and pass a large section to avr_elf32_load_records_from_section() probably resulting in a crash or in
    some cases memory corruption. The highest threat from this vulnerability is to integrity as well as system
    availability. (CVE-2021-3549)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2903
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67368467");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "binutils-2.27-28.base.1.h51.eulerosv2r7"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
