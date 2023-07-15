#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2686-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(150806);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2018-20060", "CVE-2019-11236", "CVE-2019-11324", "CVE-2020-26137");

  script_name(english:"Debian DLA-2686-1 : python-urllib3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in python-urllib3, a HTTP
client for Python. 

CVE-2018-20060

Urllib3 does not remove the Authorization HTTP header when following a
cross-origin redirect (i.e., a redirect that differs in host, port, or
scheme). This can allow for credentials in the Authorization header to
be exposed to unintended hosts or transmitted in cleartext.

CVE-2019-11236

CRLF injection is possible if the attacker controls the request
parameter.

CVE-2019-11324

Urllib3 mishandles certain cases where the desired set of CA
certificates is different from the OS store of CA certificates, which
results in SSL connections succeeding in situations where a
verification failure is the correct outcome. This is related to use of
the ssl_context, ca_certs, or ca_certs_dir argument.

CVE-2020-26137

Urllib3 allows CRLF injection if the attacker controls the HTTP
request method, as demonstrated by inserting CR and LF control
characters in the first argument of putrequest().

For Debian 9 stretch, these problems have been fixed in version
1.19.1-1+deb9u1.

We recommend that you upgrade your python-urllib3 packages.

For the detailed security status of python-urllib3 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python-urllib3

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/06/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-urllib3"
  );
  # https://security-tracker.debian.org/tracker/source-package/python-urllib3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb907009"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected python-urllib3, and python3-urllib3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26137");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-urllib3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"python-urllib3", reference:"1.19.1-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-urllib3", reference:"1.19.1-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
