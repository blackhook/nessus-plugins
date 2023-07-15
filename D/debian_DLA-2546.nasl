#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2546-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146278);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/10");

  script_cve_id("CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");

  script_name(english:"Debian DLA-2546-1 : intel-microcode security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2020-8695

Observable discrepancy in the RAPL interface for some Intel(R)
Processors may allow a privileged user to potentially enable
information disclosure via local access.

CVE-2020-8696

Improper removal of sensitive information before storage or transfer
in some Intel(R) Processors may allow an authenticated user to
potentially enable information disclosure via local access.

CVE-2020-8698

Improper isolation of shared resources in some Intel(R) Processors may
allow an authenticated user to potentially enable information
disclosure via local access.

For Debian 9 stretch, these problems have been fixed in version
3.20201118.1~deb9u1.

We recommend that you upgrade your intel-microcode packages.

For the detailed security status of intel-microcode please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/intel-microcode

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/intel-microcode"
  );
  # https://security-tracker.debian.org/tracker/source-package/intel-microcode
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?019586d4"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected intel-microcode package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/08");
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
if (deb_check(release:"9.0", prefix:"intel-microcode", reference:"3.20201118.1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
