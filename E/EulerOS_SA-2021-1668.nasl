#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147682);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id(
    "CVE-2018-12182",
    "CVE-2019-11098",
    "CVE-2019-13224",
    "CVE-2019-13225",
    "CVE-2019-14553",
    "CVE-2019-14558",
    "CVE-2019-14559",
    "CVE-2019-14563",
    "CVE-2019-14575",
    "CVE-2019-14584",
    "CVE-2019-14586",
    "CVE-2019-14587",
    "CVE-2019-14588"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : edk2 (EulerOS-SA-2021-1668)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the edk2 package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - EFI Development Kit II AARCH64 UEFI FirmwareSecurity
    Fix(es):AuthenticodeVerify() calls OpenSSLs d2i_PKCS7()
    API to parse asn encoded signed authenticode pkcs#7
    data. when this successfully returns, a type check is
    done by calling PKCS7_type_is_signed() and then
    Pkcs7->d.sign->contents->type is used. It is possible
    to construct an asn1 blob that successfully decodes and
    have d2i_PKCS7() return a valid pointer and have
    PKCS7_type_is_signed() also return success but have
    Pkcs7->d.sign be a NULL
    pointer.(CVE-2019-14584)IA32_FEATURE_CONTROL stays
    unlocked in S3 after a warm reset(CVE-2019-14588)We
    have found a TOCTOU vulnerability which allows an
    attacker with physical access to achieve code execution
    after the Boot Guard ACM computes and validates the
    hash of the IBB and measured the firmware into the TPM
    PCR0. This means the firmware will be marked as valid
    and have normal PCR0 values even though unsigned code
    has run. The root cause is when the FSP has finished
    memory init and disables MTRRs (and thereby the cache)
    in order to switch off No Evict Mode. The code doing
    this (the SecCore PeiTemporaryRamDonePpi callback), is
    executed directly from SPI flash, allowing an attacker
    to intercept execution flow. As a proof of concept we
    demonstrated that using an FPGA to substitute a single,
    targeted SPI transaction we can gain code
    execution.(CVE-2019-11098)Insufficient control flow
    management in BIOS firmware for 8th, 9th, 10th
    Generation Intel(R) Core(TM), Intel(R) Celeron(R)
    Processor 4000 & 5000 Series Processors may allow an
    authenticated user to potentially enable denial of
    service via adjacent access.(CVE-2019-14558)Logic issue
    EDK II may allow an unauthenticated user to potentially
    enable denial of service via adjacent
    access.(CVE-2019-14587)Use after free vulnerability in
    EDK II may allow an authenticated user to potentially
    enable escalation of privilege, information disclosure
    and/or denial of service via adjacent
    access.(CVE-2019-14586)A NULL Pointer Dereference in
    match_at() in regexec.c in Oniguruma 6.9.2 allows
    attackers to potentially cause denial of service by
    providing a crafted regular expression. Oniguruma
    issues often affect Ruby, as well as common optional
    libraries for PHP and Rust.(CVE-2019-13225)A
    use-after-free in onig_new_deluxe() in regext.c in
    Oniguruma 6.9.2 allows attackers to potentially cause
    information disclosure, denial of service, or possibly
    code execution by providing a crafted regular
    expression. The attacker provides a pair of a regex
    pattern and a string, with a multi-byte encoding that
    gets handled by onig_new_deluxe(). Oniguruma issues
    often affect Ruby, as well as common optional libraries
    for PHP and Rust.(CVE-2019-13224)Insufficient memory
    write check in SMM service for EDK II may allow an
    authenticated user to potentially enable escalation of
    privilege, information disclosure and/or denial of
    service via local access.(CVE-2018-12182)Logic issue in
    DxeImageVerificationHandler() for EDK II may allow an
    authenticated user to potentially enable escalation of
    privilege via local access.(CVE-2019-14575)Uncontrolled
    resource consumption in EDK II may allow an
    unauthenticated user to potentially enable denial of
    service via network access.(CVE-2019-14559)Integer
    truncation in EDK II may allow an authenticated user to
    potentially enable escalation of privilege via local
    access.(CVE-2019-14563)Improper authentication in EDK
    II may allow a privileged user to potentially enable
    information disclosure via network
    access.(CVE-2019-14553)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1668
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25e9e9cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected edk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["edk2-aarch64-201903-2.9.1.2.33"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "edk2");
}
