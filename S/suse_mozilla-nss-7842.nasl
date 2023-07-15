#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57226);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2011-2372",
    "CVE-2011-2996",
    "CVE-2011-2998",
    "CVE-2011-2999",
    "CVE-2011-3000",
    "CVE-2011-3001",
    "CVE-2011-3389",
    "CVE-2011-3647",
    "CVE-2011-3648",
    "CVE-2011-3649",
    "CVE-2011-3650",
    "CVE-2011-3651",
    "CVE-2011-3653",
    "CVE-2011-3655"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SuSE 10 Security Update : mozilla-nss (ZYPP Patch Number 7842) (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"This update to version 3.13.1 of mozilla-nss fixes the following
issues :

  - Explicitly distrust DigiCert Sdn. Bhd (bmo#698753)

  - Better SHA-224 support (bmo#647706)

  - Fix a regression (causing hangs in some situations)
    introduced in 3.13 (bmo#693228)

  - SSL 2.0 is disabled by default

  - A defense against the SSL 3.0 and TLS 1.0 CBC chosen
    plaintext attack demonstrated by Rizzo and Duong
    (CVE-2011-3389) has been enabled by default. Set the
    SSL_CBC_RANDOM_IV SSL option to PR_FALSE to disable it.

  - Support SHA-224

  - Add PORT_ErrorToString and PORT_ErrorToName to return
    the error message and symbolic name of an NSS error code

  - Add NSS_GetVersion to return the NSS version string

  - Add experimental support of RSA-PSS to the softoken only

  - NSS_NoDB_Init does not try to open /pkcs11.txt and
    /secmod.db anymore (bmo#641052)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-2372.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-2996.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-2998.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-2999.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3000.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3001.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3389.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3647.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3648.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3649.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3650.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3651.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3653.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3655.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 7842.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-devel-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mozilla-nss-tools-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-devel-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mozilla-nss-tools-3.13.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.1-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
