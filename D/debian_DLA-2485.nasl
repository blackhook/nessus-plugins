#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2485-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143594);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Debian DLA-2485-1 : golang-golang-x-net-dev security update (Ping Flood) (Reset Flood)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The http2 server support in this package was vulnerable to certain
types of DOS attacks.

CVE-2019-9512

This code was vulnerable to ping floods, potentially leading to a
denial of service. The attacker sends continual pings to an HTTP/2
peer, causing the peer to build an internal queue of responses.
Depending on how efficiently this data is queued, this can consume
excess CPU, memory, or both.

CVE-2019-9514

This code was vulnerable to a reset flood, potentially leading to a
denial of service. The attacker opens a number of streams and sends an
invalid request over each stream that should solicit a stream of
RST_STREAM frames from the peer. Depending on how the peer queues the
RST_STREAM frames, this can consume excess memory, CPU, or both.

For Debian 9 stretch, these problems have been fixed in version
1:0.0+git20161013.8b4af36+dfsg-3+deb9u1.

We recommend that you upgrade your golang-golang-x-net-dev packages.

For the detailed security status of golang-golang-x-net-dev please
refer to its security tracker page at:
https://security-tracker.debian.org/tracker/golang-golang-x-net-dev

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/golang-golang-x-net-dev"
  );
  # https://security-tracker.debian.org/tracker/source-package/golang-golang-x-net-dev
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2f3b613"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go.net-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-golang-x-net-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"golang-go.net-dev", reference:"1:0.0+git20161013.8b4af36+dfsg-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"golang-golang-x-net-dev", reference:"1:0.0+git20161013.8b4af36+dfsg-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
