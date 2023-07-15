#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-2f8f5f75f1.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120326);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-16790");
  script_xref(name:"FEDORA", value:"2018-2f8f5f75f1");

  script_name(english:"Fedora 29 : mongo-c-driver (2018-2f8f5f75f1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**libbson 1.13.0**

**Features:**

  - New functions to save and restore progress of a
    bson_iter_t: bson_iter_key_len, bson_iter_offset, and
    son_iter_init_from_data_at_offset Additional functions
    bson_iter_overwrite_date_time, bson_iter_overwrite_oid,
    and bson_iter_overwrite_timestamp. All fixed-length BSON
    values can now be updated in place.

**Bug fixes:**

  - Fix crash when iterating corrupt BSON.

---

**libmongoc 1.13.0**

**Features:**

  - Report a new error code, MONGOC_ERROR_GRIDFS_CORRUPT,
    when a chunk larger than chunkSize is detected. Before,
    the driver had crashed with an assert. Restructure of
    install directory. All mongoc headers are under mongoc/
    and all bson headers are under bson/. The preferred way
    of including the headers are mongoc/mongoc.h and
    bson/bson.h respectively. Forwarding headers in the root
    are provided for backwards compatibility.

  - The default CMake build type had been unspecified, now
    it is RelWithDebInfo.

  - Support LibreSSL 2.7+.

**Bug fixes:**

  - mongoc_collection_replace_one is now a correctly
    exported symbol.

  - Fix multiple issues with readConcern and writeConcern
    inheritance.

  - Fix rare crash with mongodb+srv URIs on Windows.

  - mongoc_gridfs_create_file_from_stream ignored errors
    while writing chunks to the server.

  - The following functions should not have taken a
    'bypassDocumentValidation' option in bson_t *opts, the
    option is now prohibited :

  - mongoc_bulk_operation_insert_with_opts

  - mongoc_bulk_operation_update_one_with_opts

  - mongoc_bulk_operation_update_many_with_opts

  - mongoc_bulk_operation_replace_one_with_opts

  - The heartbeat-succeeded and heartbeat-failed events
    (part of SDAM Monitoring) had uninitialized 'duration'
    fields, they are now set correctly.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-2f8f5f75f1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mongo-c-driver package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mongo-c-driver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"mongo-c-driver-1.13.0-1.fc29")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mongo-c-driver");
}
