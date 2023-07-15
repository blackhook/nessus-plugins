#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2402-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141271);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/12");

  script_cve_id("CVE-2019-11840", "CVE-2019-11841", "CVE-2020-9283");

  script_name(english:"Debian DLA-2402-1 : golang-go.crypto security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2019-11840

An issue was discovered in supplementary Go cryptography libraries,
aka golang-googlecode-go-crypto. If more than 256 GiB of keystream is
generated, or if the counter otherwise grows greater than 32 bits, the
amd64 implementation will first generate incorrect output, and then
cycle back to previously generated keystream. Repeated keystream bytes
can lead to loss of confidentiality in encryption applications, or to
predictability in CSPRNG applications.

CVE-2019-11841

A message-forgery issue was discovered in
crypto/openpgp/clearsign/clearsign.go in supplementary Go cryptography
libraries. The 'Hash' Armor Header specifies the message digest
algorithm(s) used for the signature. Since the library skips Armor
Header parsing in general, an attacker can not only embed arbitrary
Armor Headers, but also prepend arbitrary text to cleartext messages
without invalidating the signatures.

CVE-2020-9283

golang.org/x/crypto allows a panic during signature verification in
the golang.org/x/crypto/ssh package. A client can attack an SSH server
that accepts public keys. Also, a server can attack any SSH client.

For Debian 9 stretch, these problems have been fixed in version
1:0.0~git20170407.0.55a552f+REALLY.0.0~git20161012.0.5f31782-1+deb8u1.

We recommend that you upgrade your golang-go.crypto packages.

For the detailed security status of golang-go.crypto please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/golang-go.crypto

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/golang-go.crypto"
  );
  # https://security-tracker.debian.org/tracker/source-package/golang-go.crypto
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e94138e5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11841");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go.crypto-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-golang-x-crypto-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");
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
if (deb_check(release:"9.0", prefix:"golang-go.crypto-dev", reference:"1:0.0~git20170407.0.55a552f+REALLY.0.0~git20161012.0.5f31782-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"golang-golang-x-crypto-dev", reference:"1:0.0~git20170407.0.55a552f+REALLY.0.0~git20161012.0.5f31782-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
