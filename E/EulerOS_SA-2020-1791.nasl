#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138010);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-13224",
    "CVE-2019-13225",
    "CVE-2019-14553",
    "CVE-2019-14559",
    "CVE-2019-14563",
    "CVE-2019-14575"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : edk (EulerOS-SA-2020-1791)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the edk package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A NULL Pointer Dereference in match_at() in regexec.c
    in Oniguruma 6.9.2 allows attackers to potentially
    cause denial of service by providing a crafted regular
    expression. Oniguruma issues often affect Ruby, as well
    as common optional libraries for PHP and
    Rust.(CVE-2019-13225)

  - A use-after-free in onig_new_deluxe() in regext.c in
    Oniguruma 6.9.2 allows attackers to potentially cause
    information disclosure, denial of service, or possibly
    code execution by providing a crafted regular
    expression. The attacker provides a pair of a regex
    pattern and a string, with a multi-byte encoding that
    gets handled by onig_new_deluxe(). Oniguruma issues
    often affect Ruby, as well as common optional libraries
    for PHP and Rust.(CVE-2019-13224)

  - EDK2 is a set of cross-platform firmware development
    environment based on UEFI and PI specifications in the
    TianoCore community.There is a security vulnerability
    in EDK2. The vulnerability stems from the fact that
    the'DxeImageVerificationHandler()' function does not
    correctly check whether unsigned EFI files are allowed
    to be loaded. Attackers can use this vulnerability to
    bypass verification.(CVE-2019-14575)

  - EDK2 is a set of cross-platform firmware development
    environment based on UEFI and PI specifications in the
    TianoCore community.The'ArpOnFrameRcvdDpc' function in
    EDK2 has a resource management error vulnerability. The
    vulnerability stems from the improper management of
    system resources (such as memory, disk space, files,
    etc.) by network systems or products.(CVE-2019-14559)

  - EDK2 is a set of cross-platform firmware development
    environment based on UEFI and PI specifications in the
    TianoCore community.An input verification error
    vulnerability exists in EDK2. The vulnerability stems
    from the fact that the network system or product did
    not correctly verify the input data.(CVE-2019-14563)

  - EDK2 is a set of cross-platform firmware development
    environment based on UEFI and PI specifications in the
    TianoCore community.There is a security vulnerability
    in EDK2. The source of the vulnerability will receive
    an invalid certificate when HTTPS-over-IPv6 is started.
    Attackers can use this vulnerability to implement
    man-in-the-middle attacks.(CVE-2019-14553)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1791
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4e891d3");
  script_set_attribute(attribute:"solution", value:
"Update the affected edk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13224");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:edk");
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

pkgs = ["edk-2.0-30.107"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "edk");
}
