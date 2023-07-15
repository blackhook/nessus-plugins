#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2435-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142632);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-9497", "CVE-2020-9498");

  script_name(english:"Debian DLA-2435-1 : guacamole-server security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The server component of Apache Guacamole, a remote desktop gateway,
did not properly validate data received from RDP servers. This could
result in information disclosure or even the execution of arbitrary
code.

CVE-2020-9497

Apache Guacamole does not properly validate data received from RDP
servers via static virtual channels. If a user connects to a malicious
or compromised RDP server, specially crafted PDUs could result in
disclosure of information within the memory of the guacd process
handling the connection.

CVE-2020-9498

Apache Guacamole may mishandle pointers involved in processing data
received via RDP static virtual channels. If a user connects to a
malicious or compromised RDP server, a series of specially crafted
PDUs could result in memory corruption, possibly allowing arbitrary
code to be executed with the privileges of the running guacd process.

For Debian 9 stretch, these problems have been fixed in version
0.9.9-2+deb9u1.

We recommend that you upgrade your guacamole-server packages.

For the detailed security status of guacamole-server please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/guacamole-server

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/guacamole-server"
  );
  # https://security-tracker.debian.org/tracker/source-package/guacamole-server
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7763c5e7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9498");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:guacd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libguac-client-rdp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libguac-client-ssh0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libguac-client-telnet0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libguac-client-vnc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libguac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libguac11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");
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
if (deb_check(release:"9.0", prefix:"guacd", reference:"0.9.9-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libguac-client-rdp0", reference:"0.9.9-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libguac-client-ssh0", reference:"0.9.9-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libguac-client-telnet0", reference:"0.9.9-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libguac-client-vnc0", reference:"0.9.9-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libguac-dev", reference:"0.9.9-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libguac11", reference:"0.9.9-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
