#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libfreebl3-1201.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40652);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408");

  script_name(english:"openSUSE Security Update : libfreebl3 (libfreebl3-1201)");
  script_summary(english:"Check for the libfreebl3-1201 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla NSS security framework was updated to version 3.12.3.1.

CVE-2009-2404 / MFSA 2009-43 : Heap-based buffer overflow in a
regular-expression parser in Mozilla Network Security Services (NSS)
before 3.12.3, as used in Firefox, Thunderbird, SeaMonkey, Evolution,
Pidgin, and AOL Instant Messenger (AIM), allows remote SSL servers to
cause a denial of service (application crash) or possibly execute
arbitrary code via a long domain name in the subject's Common Name
(CN) field of an X.509 certificate, related to the cert_TestHostName
function.

MFSA 2009-42 / CVE-2009-2408: IOActive security researcher Dan
Kaminsky reported a mismatch in the treatment of domain names in SSL
certificates between SSL clients and the Certificate Authorities (CA)
which issue server certificates. In particular, if a malicious person
requested a certificate for a host name with an invalid null character
in it most CAs would issue the certificate if the requester owned the
domain specified after the null, while most SSL clients (browsers)
ignored that part of the name and used the unvalidated part in front
of the null. This made it possible for attackers to obtain
certificates that would function for any site they wished to target.
These certificates could be used to intercept and potentially alter
encrypted communication between the client and a server such as
sensitive bank account transactions. This vulnerability was
independently reported to us by researcher Moxie Marlinspike who also
noted that since Firefox relies on SSL to protect the integrity of
security updates this attack could be used to serve malicious updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522602"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libfreebl3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"libfreebl3-3.12.3.1-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-nss-3.12.3.1-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-nss-devel-3.12.3.1-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"mozilla-nss-tools-3.12.3.1-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.12.3.1-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.12.3.1-1.1.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-nss");
}
