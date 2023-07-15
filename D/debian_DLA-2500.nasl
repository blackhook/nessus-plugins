#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2500-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144497);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-8284", "CVE-2020-8285", "CVE-2020-8286");
  script_xref(name:"IAVA", value:"2020-A-0581");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2500-1 : curl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in curl, a command line tool
for transferring data with URL syntax and an easy-to-use client-side
URL transfer library.

CVE-2020-8284

When curl performs a passive FTP transfer, it first tries the EPSV
command and if that is not supported, it falls back to using PASV.
Passive mode is what curl uses by default. A server response to a PASV
command includes the (IPv4) address and port number for the client to
connect back to in order to perform the actual data transfer. This is
how the FTP protocol is designed to work. A malicious server can use
the PASV response to trick curl into connecting back to a given IP
address and port, and this way potentially make curl extract
information about services that are otherwise private and not
disclosed, for example doing port scanning and service banner
extractions.

The IP address part of the response is now ignored by
default, by making CURLOPT_FTP_SKIP_PASV_IP default to 1L
instead of previously being 0L. This has the minor drawback
that a small fraction of use cases might break, when a
server truly needs the client to connect back to a different
IP address than what the control connection uses and for
those CURLOPT_FTP_SKIP_PASV_IP can be set to 0L. The same
goes for the command line tool, which then might need

--no-ftp-skip-pasv-ip set to prevent curl from ignoring the
address in the server response.

CVE-2020-8285

libcurl offers a wildcard matching functionality, which allows a
callback (set with CURLOPT_CHUNK_BGN_FUNCTION) to return information
back to libcurl on how to handle a specific entry in a directory when
libcurl iterates over a list of all available entries. When this
callback returns CURL_CHUNK_BGN_FUNC_SKIP, to tell libcurl to not deal
with that file, the internal function in libcurl then calls itself
recursively to handle the next directory entry. If there's a
sufficient amount of file entries and if the callback returns 'skip'
enough number of times, libcurl runs out of stack space. The exact
amount will of course vary with platforms, compilers and other
environmental factors. The content of the remote directory is not kept
on the stack, so it seems hard for the attacker to control exactly
what data that overwrites the stack - however it remains a
denial of service vector as a malicious user who controls a server
that a libcurl-using application works with under these premises can
trigger a crash.

The internal function is rewritten to instead and more
appropriately use an ordinary loop instead of the recursive
approach. This way, the stack use will remain the same no
matter how many files that are skipped.

CVE-2020-8286

libcurl offers 'OCSP stapling' via the CURLOPT_SSL_VERIFYSTATUS
option. When set, libcurl verifies the OCSP response that a server
responds with as part of the TLS handshake. It then aborts the TLS
negotiation if something is wrong with the response. The same feature
can be enabled with --cert-status using the curl tool. As part of the
OCSP response verification, a client should verify that the response
is indeed set out for the correct certificate. This step was not
performed by libcurl when built or told to use OpenSSL as TLS backend.
This flaw would allow an attacker, who perhaps could have breached a
TLS server, to provide a fraudulent OCSP response that would appear
fine, instead of the real one. Like if the original certificate
actually has been revoked.

The OCSP response checker function now also verifies that
the certificate id is the correct one.

For Debian 9 stretch, these problems have been fixed in version
7.52.1-5+deb9u13.

We recommend that you upgrade your curl packages.

For the detailed security status of curl please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/curl

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/curl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8286");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-gnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-nss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcurl4-openssl-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"9.0", prefix:"curl", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-dbg", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-gnutls", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl3-nss", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-doc", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-gnutls-dev", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-nss-dev", reference:"7.52.1-5+deb9u13")) flag++;
if (deb_check(release:"9.0", prefix:"libcurl4-openssl-dev", reference:"7.52.1-5+deb9u13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
