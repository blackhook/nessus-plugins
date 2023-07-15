#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2388-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141062);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2018-12404", "CVE-2018-18508", "CVE-2019-11719", "CVE-2019-11729", "CVE-2019-11745", "CVE-2019-17006", "CVE-2019-17007", "CVE-2020-12399", "CVE-2020-12400", "CVE-2020-12401", "CVE-2020-12402", "CVE-2020-12403", "CVE-2020-6829");

  script_name(english:"Debian DLA-2388-1 : nss security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Various vulnerabilities were fixed in nss, the Network Security
Service libraries.

CVE-2018-12404

Cache side-channel variant of the Bleichenbacher attack.

CVE-2018-18508

NULL pointer dereference in several CMS functions resulting in a
denial of service.

CVE-2019-11719

Out-of-bounds read when importing curve25519 private key.

CVE-2019-11729

Empty or malformed p256-ECDH public keys may trigger a segmentation
fault.

CVE-2019-11745

Out-of-bounds write when encrypting with a block cipher.

CVE-2019-17006

Some cryptographic primitives did not check the length of the input
text, potentially resulting in overflows.

CVE-2019-17007

Handling of Netscape Certificate Sequences may crash with a NULL
dereference leading to a denial of service.

CVE-2020-12399

Force a fixed length for DSA exponentiation.

CVE-2020-6829 CVE-2020-12400

Side channel attack on ECDSA signature generation.

CVE-2020-12401

ECDSA timing attack mitigation bypass.

CVE-2020-12402

Side channel vulnerabilities during RSA key generation.

CVE-2020-12403

CHACHA20-POLY1305 decryption with undersized tag leads to
out-of-bounds read.

For Debian 9 stretch, these problems have been fixed in version
2:3.26.2-1.1+deb9u2.

We recommend that you upgrade your nss packages.

For the detailed security status of nss please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/nss

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/nss"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libnss3", reference:"2:3.26.2-1.1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3-dbg", reference:"2:3.26.2-1.1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3-dev", reference:"2:3.26.2-1.1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnss3-tools", reference:"2:3.26.2-1.1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
