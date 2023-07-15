#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152287);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/11");

  script_cve_id(
    "CVE-2020-15389",
    "CVE-2020-27814",
    "CVE-2020-27823",
    "CVE-2020-27824",
    "CVE-2020-27841",
    "CVE-2020-27843",
    "CVE-2020-27845"
  );

  script_name(english:"EulerOS 2.0 SP9 : openjpeg2 (EulerOS-SA-2021-2276)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openjpeg2 package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in OpenJPEG's encoder. This flaw
    allows an attacker to pass specially crafted x,y offset
    input to OpenJPEG to use during encoding. The highest
    threat from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2020-27823)

  - A flaw was found in OpenJPEG's encoder in the
    opj_dwt_calc_explicit_stepsizes() function. This flaw
    allows an attacker who can supply crafted input to
    decomposition levels to cause a buffer overflow. The
    highest threat from this vulnerability is to system
    availability.(CVE-2020-27824)

  - jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a
    use-after-free that can be triggered if there is a mix
    of valid and invalid files in a directory operated on
    by the decompressor. Triggering a double-free may also
    be possible. This is related to calling
    opj_image_destroy twice.(CVE-2020-15389)

  - A flaw was found in OpenJPEG in versions prior to
    2.4.0. This flaw allows an attacker to provide
    specially crafted input to the conversion or encoding
    functionality, causing an out-of-bounds read. The
    highest threat from this vulnerability is system
    availability.(CVE-2020-27843)

  - A heap-buffer overflow was found in the way openjpeg2
    handled certain PNG format files. An attacker could use
    this flaw to cause an application crash or in some
    cases execute arbitrary code with the permission of the
    user running such an application.(CVE-2020-27814)

  - There's a flaw in openjpeg in versions prior to 2.4.0
    in src/lib/openjp2/pi.c. When an attacker is able to
    provide crafted input to be processed by the openjpeg
    encoder, this could cause an out-of-bounds read. The
    greatest impact from this flaw is to application
    availability.(CVE-2020-27841)

  - There's a flaw in src/lib/openjp2/pi.c of openjpeg in
    versions prior to 2.4.0. If an attacker is able to
    provide untrusted input to openjpeg's
    conversion/encoding functionality, they could cause an
    out-of-bounds read. The highest impact of this flaw is
    to application availability.(CVE-2020-27845)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2276
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eab3341a");
  script_set_attribute(attribute:"solution", value:
"Update the affected openjpeg2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27823");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openjpeg2");
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
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["openjpeg2-2.3.1-2.h3.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg2");
}
