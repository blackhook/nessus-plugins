#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2588-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147685);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2021-20234", "CVE-2021-20235");

  script_name(english:"Debian DLA-2588-1 : zeromq3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two security issues have been detected in zeromq3.

CVE-2021-20234

Memory leak in client induced by malicious server(s) without
CURVE/ZAP.

From issue description [1]. When a pipe processes a
delimiter and is already not in active state but still has
an unfinished message, the message is leaked.

CVE-2021-20235

Heap overflow when receiving malformed ZMTP v1 packets.

From issue description [2]. The static allocator was
implemented to shrink its recorded size similarly to the
shared allocator. But it does not need to, and it should
not, because unlike the shared one the static allocator
always uses a static buffer, with a size defined by the
ZMQ_IN_BATCH_SIZE socket option (default 8192), so changing
the size opens the library to heap overflows. The static
allocator is used only with ZMTP v1 peers.

[1]
https://github.com/zeromq/libzmq/security/advisories/GHSA-wfr2-29gj-5w
87 [2]
https://github.com/zeromq/libzmq/security/advisories/GHSA-fc3w-qxf5-7h
p6

For Debian 9 stretch, these problems have been fixed in version
4.2.1-4+deb9u4.

We recommend that you upgrade your zeromq3 packages.

For the detailed security status of zeromq3 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/zeromq3

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://github.com/zeromq/libzmq/security/advisories/GHSA-fc3w-qxf5-7hp6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73f24c70"
  );
  # https://github.com/zeromq/libzmq/security/advisories/GHSA-wfr2-29gj-5w87
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e78b960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/zeromq3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/zeromq3"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected libzmq3-dev, libzmq5, and libzmq5-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20235");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzmq3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzmq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzmq5-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");
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
if (deb_check(release:"9.0", prefix:"libzmq3-dev", reference:"4.2.1-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libzmq5", reference:"4.2.1-4+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libzmq5-dbg", reference:"4.2.1-4+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
