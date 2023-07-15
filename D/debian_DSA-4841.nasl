#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4841. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145523);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/01");

  script_cve_id("CVE-2019-19728", "CVE-2020-12693", "CVE-2020-27745", "CVE-2020-27746");
  script_xref(name:"DSA", value:"4841");

  script_name(english:"Debian DSA-4841-1 : slurm-llnl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in the Simple Linux Utility
for Resource Management (SLURM), a cluster resource management and job
scheduling system, which could result in denial of service,
information disclosure or privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/slurm-llnl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/slurm-llnl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4841"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the slurm-llnl packages.

For the stable distribution (buster), these problems have been fixed
in version 18.08.5.2-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-llnl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");
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
if (deb_check(release:"10.0", prefix:"libpam-slurm", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libpmi0", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libpmi0-dev", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libpmi2-0", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libpmi2-0-dev", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libslurm-dev", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libslurm-perl", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libslurm33", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libslurmdb-dev", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libslurmdb-perl", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libslurmdb33", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-client", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-client-emulator", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-wlm", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-wlm-basic-plugins", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-wlm-basic-plugins-dev", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-wlm-doc", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-wlm-emulator", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurm-wlm-torque", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurmctld", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurmd", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"slurmdbd", reference:"18.08.5.2-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"sview", reference:"18.08.5.2-1+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
