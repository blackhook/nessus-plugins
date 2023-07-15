#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2591-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147797);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/17");

  script_cve_id("CVE-2017-15041", "CVE-2018-16873", "CVE-2018-16874", "CVE-2019-16276", "CVE-2019-17596", "CVE-2019-9741", "CVE-2021-3114");

  script_name(english:"Debian DLA-2591-1 : golang-1.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in the Go programming
language. An attacker could trigger a denial of service (DoS), bypasss
access control, and execute arbitrary code on the developer's
computer.

CVE-2017-15041

Go allows 'go get' remote command execution. Using custom domains, it
is possible to arrange things so that example.com/pkg1 points to a
Subversion repository but example.com/pkg1/pkg2 points to a Git
repository. If the Subversion repository includes a Git checkout in
its pkg2 directory and some other work is done to ensure the proper
ordering of operations, 'go get' can be tricked into reusing this Git
checkout for the fetch of code from pkg2. If the Subversion
repository's Git checkout has malicious commands in .git/hooks/, they
will execute on the system running 'go get.'

CVE-2018-16873

The 'go get' command is vulnerable to remote code execution when
executed with the -u flag and the import path of a malicious Go
package, as it may treat the parent directory as a Git repository
root, containing malicious configuration.

CVE-2018-16874

The 'go get' command is vulnerable to directory traversal when
executed with the import path of a malicious Go package which contains
curly braces (both '{' and '}' characters). The attacker can cause an
arbitrary filesystem write, which can lead to code execution.

CVE-2019-9741

In net/http, CRLF injection is possible if the attacker controls a url
parameter, as demonstrated by the second argument to http.NewRequest
with \r\n followed by an HTTP header or a Redis command.

CVE-2019-16276

Go allows HTTP Request Smuggling.

CVE-2019-17596

Go can panic upon an attempt to process network traffic containing an
invalid DSA public key. There are several attack scenarios, such as
traffic from a client to a server that verifies client certificates.

CVE-2021-3114

crypto/elliptic/p224.go can generate incorrect outputs, related to an
underflow of the lowest limb during the final complete reduction in
the P-224 field.

For Debian 9 stretch, these problems have been fixed in version
1.7.4-2+deb9u3.

We recommend that you upgrade your golang-1.7 packages.

For the detailed security status of golang-1.7 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/golang-1.7

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/golang-1.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/golang-1.7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-1.7-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"golang-1.7", reference:"1.7.4-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"golang-1.7-doc", reference:"1.7.4-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"golang-1.7-go", reference:"1.7.4-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"golang-1.7-src", reference:"1.7.4-2+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
