#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65719);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SuSE 10 Security Update : OpenSSL (ZYPP Patch Number 8517)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"OpenSSL has been updated to fix several security issues :

  - Avoid the openssl CRIME attack by disabling SSL
    compression by default. Setting the environment variable
    'OPENSSL_NO_DEFAULT_ZLIB' to 'no' enables compression
    again. (CVE-2012-4929)

    Please note that openssl on SUSE Linux Enterprise 10 is
    not built with compression support.

  - Timing attacks against TLS could be used by physically
    local attackers to gain access to transmitted plain text
    or private keymaterial. This issue is also known as the
    'Lucky-13' issue. (CVE-2013-0169)

  - A OCSP invalid key denial of service issue was fixed.
    (CVE-2013-0166)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-4929.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0166.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0169.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 8517.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"openssl-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"openssl-devel-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"openssl-32bit-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"openssl-devel-32bit-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"openssl-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"openssl-devel-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"openssl-doc-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"openssl-32bit-0.9.8a-18.76.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"openssl-devel-32bit-0.9.8a-18.76.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
