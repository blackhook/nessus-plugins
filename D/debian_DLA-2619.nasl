#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2619-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148322);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2021-23336", "CVE-2021-3177", "CVE-2021-3426");

  script_name(english:"Debian DLA-2619-1 : python3.5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Three security issues have been discovered in python3.5 :

CVE-2021-3177

Python 3.x has a buffer overflow in PyCArg_repr in _ctypes/callproc.c,
which may lead to remote code execution in certain Python applications
that accept floating-point numbers as untrusted input. This occurs
because sprintf is used unsafely.

CVE-2021-3426

Running `pydoc -p` allows other local users to extract arbitrary
files. The `/getfile?key=path` URL allows to read arbitrary file on
the filesystem.

The fix removes the 'getfile' feature of the pydoc module
which could be abused to read arbitrary files on the disk
(directory traversal vulnerability).

CVE-2021-23336

The Python3.5 vulnerable to Web Cache Poisoning via
urllib.parse.parse_qsl and urllib.parse.parse_qs by using a vector
called parameter cloaking. When the attacker can separate query
parameters using a semicolon (;), they can cause a difference in the
interpretation of the request between the proxy (running with default
configuration) and the server. This can result in malicious requests
being cached as completely safe ones, as the proxy would usually not
see the semicolon as a separator, and therefore would not include it
in a cache key of an unkeyed parameter.

**Attention, API-change!** Please be sure your software is
working properly if it uses `urllib.parse.parse_qs` or
`urllib.parse.parse_qsl`, `cgi.parse` or
`cgi.parse_multipart`.

Earlier Python versions allowed using both ``;`` and ``&``
as query parameter separators in `urllib.parse.parse_qs` and
`urllib.parse.parse_qsl`. Due to security concerns, and to
conform with newer W3C recommendations, this has been
changed to allow only a single separator key, with ``&`` as
the default. This change also affects `cgi.parse` and
`cgi.parse_multipart` as they use the affected functions
internally. For more details, please see their respective
documentation.

For Debian 9 stretch, these problems have been fixed in version
3.5.3-1+deb9u4.

We recommend that you upgrade your python3.5 packages.

For the detailed security status of python3.5 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python3.5

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python3.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/python3.5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-venv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/06");
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
if (deb_check(release:"9.0", prefix:"idle-python3.5", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-dbg", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-dev", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-minimal", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-stdlib", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-testsuite", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-dbg", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-dev", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-doc", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-examples", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-minimal", reference:"3.5.3-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-venv", reference:"3.5.3-1+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
