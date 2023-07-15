#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-628.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110530);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-1000338", "CVE-2016-1000339", "CVE-2016-1000340", "CVE-2016-1000341", "CVE-2016-1000342", "CVE-2016-1000343", "CVE-2016-1000344", "CVE-2016-1000345", "CVE-2016-1000346", "CVE-2016-1000352", "CVE-2017-13098");

  script_name(english:"openSUSE Security Update : bouncycastle (openSUSE-2018-628)");
  script_summary(english:"Check for the openSUSE-2018-628 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bouncycastle to version 1.59 fixes the following
issues :

These security issues were fixed :

  - CVE-2017-13098: BouncyCastle, when configured to use the
    JCE (Java Cryptography Extension) for cryptographic
    functions, provided a weak Bleichenbacher oracle when
    any TLS cipher suite using RSA key exchange was
    negotiated. An attacker can recover the private key from
    a vulnerable application. This vulnerability is referred
    to as 'ROBOT' (bsc#1072697).

  - CVE-2016-1000338: Ensure full validation of ASN.1
    encoding of signature on verification. It was possible
    to inject extra elements in the sequence making up the
    signature and still have it validate, which in some
    cases may have allowed the introduction of 'invisible'
    data into a signed structure (bsc#1095722).

  - CVE-2016-1000339: Prevent AESEngine key information leak
    via lookup table accesses (boo#1095853).

  - CVE-2016-1000340: Preventcarry propagation bugs in the
    implementation of squaring for several raw math classes
    (boo#1095854).

  - CVE-2016-1000341: Fix DSA signature generation
    vulnerability to timing attack (boo#1095852).

  - CVE-2016-1000341: DSA signature generation was
    vulnerable to timing attack. Where timings can be
    closely observed for the generation of signatures may
    have allowed an attacker to gain information about the
    signature's k value and ultimately the private value as
    well (bsc#1095852).

  - CVE-2016-1000342: Ensure that ECDSA does fully validate
    ASN.1 encoding of signature on verification. It was
    possible to inject extra elements in the sequence making
    up the signature and still have it validate, which in
    some cases may have allowed the introduction of
    'invisible' data into a signed structure (bsc#1095850).

  - CVE-2016-1000343: Prevent weak default settings for
    private DSA key pair generation (boo#1095849).

  - CVE-2016-1000344: Removed DHIES from the provider to
    disable the unsafe usage of ECB mode (boo#1096026).

  - CVE-2016-1000345: The DHIES/ECIES CBC mode was
    vulnerable to padding oracle attack. In an environment
    where timings can be easily observed, it was possible
    with enough observations to identify when the decryption
    is failing due to padding (bsc#1096025).

  - CVE-2016-1000346: The other party DH public key was not
    fully validated. This could have caused issues as
    invalid keys could be used to reveal details about the
    other party's private key where static Diffie-Hellman is
    in use (bsc#1096024).

  - CVE-2016-1000352: Remove ECIES from the provider to
    disable the unsafe usage of ECB mode (boo#1096022)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096026"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bouncycastle packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bouncycastle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bouncycastle-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"bouncycastle-1.59-23.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bouncycastle-javadoc-1.59-23.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bouncycastle / bouncycastle-javadoc");
}
