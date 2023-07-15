#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1418-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110948);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1000338", "CVE-2016-1000339", "CVE-2016-1000341", "CVE-2016-1000342", "CVE-2016-1000343", "CVE-2016-1000345", "CVE-2016-1000346");

  script_name(english:"Debian DLA-1418-1 : bouncycastle security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were found in Bouncy Castle, a Java
implementation of cryptographic algorithms.

CVE-2016-1000338 DSA does not fully validate ASN.1 encoding of
signature on verification. It is possible to inject extra elements in
the sequence making up the signature and still have it validate, which
in some cases may allow the introduction of 'invisible' data into a
signed structure.

CVE-2016-1000339 Previously the primary engine class used for AES was
AESFastEngine. Due to the highly table driven approach used in the
algorithm it turns out that if the data channel on the CPU can be
monitored the lookup table accesses are sufficient to leak information
on the AES key being used. There was also a leak in AESEngine although
it was substantially less. AESEngine has been modified to remove any
signs of leakage and is now the primary AES class for the BC JCE
provider. Use of AESFastEngine is now only recommended where otherwise
deemed appropriate.

CVE-2016-1000341 DSA signature generation is vulnerable to timing
attack. Where timings can be closely observed for the generation of
signatures, the lack of blinding may allow an attacker to gain
information about the signature's k value and ultimately the private
value as well.

CVE-2016-1000342 ECDSA does not fully validate ASN.1 encoding of
signature on verification. It is possible to inject extra elements in
the sequence making up the signature and still have it validate, which
in some cases may allow the introduction of 'invisible' data into a
signed structure.

CVE-2016-1000343 The DSA key pair generator generates a weak private
key if used with default values. If the JCA key pair generator is not
explicitly initialised with DSA parameters, 1.55 and earlier generates
a private value assuming a 1024 bit key size. In earlier releases this
can be dealt with by explicitly passing parameters to the key pair
generator.

CVE-2016-1000345 The DHIES/ECIES CBC mode is vulnerable to padding
oracle attack. In an environment where timings can be easily observed,
it is possible with enough observations to identify when the
decryption is failing due to padding.

CVE-2016-1000346 In the Bouncy Castle JCE Provider the other party DH
public key is not fully validated. This can cause issues as invalid
keys can be used to reveal details about the other party's private key
where static Diffie-Hellman is in use. As of this release the key
parameters are checked on agreement calculation.

For Debian 8 'Jessie', these problems have been fixed in version
1.49+dfsg-3+deb8u3.

We recommend that you upgrade your bouncycastle packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/bouncycastle"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcmail-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpg-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpkix-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcpkix-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbcprov-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"libbcmail-java", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcmail-java-doc", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpg-java", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpg-java-doc", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpkix-java", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcpkix-java-doc", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcprov-java", reference:"1.49+dfsg-3+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libbcprov-java-doc", reference:"1.49+dfsg-3+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
