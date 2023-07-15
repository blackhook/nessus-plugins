#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109724);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/09");

  script_name(english:"PII Information Removed From Scan Results");
  script_summary(english:"Removes PII usernames/paths from KB and scratchpad entries.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin removes PII usernames/paths from KB/scratchpad entries.");
  script_set_attribute(attribute:"description", value:
"This plugin digs through known KB and scratchpad values which can
contain personally identified information, and removes and replaces
the keys and values with sanitized versions.

Note that Tenable must be contacted to enable this feature.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include('artifact_scrub_list.inc');
include('data_protection.inc');

#######
# KBs #
#######
foreach kb_key_pattern (make_list(data_protection::kb_scrub_list_users, data_protection::kb_scrub_list_passwords))
{
  current_kb_list = get_kb_list(kb_key_pattern);
  if(!isnull(current_kb_list))
  {
    key_list = make_list(keys(current_kb_list));
    value_list = make_list(current_kb_list);
    max_index = max_index(key_list);
    for(i = 0; i < max_index; i++) 
    {
      kb_key = key_list[i];
      kb_value = value_list[i];
      sanitized = data_protection::sanitize_userpass(text:kb_value);
      if (kb_value != sanitized)
      {
        if(!isnull(sanitized))
        {
          rm_kb_item(name:kb_key, value:kb_value);
          set_kb_item(name:kb_key, value:sanitized);
        }
      }
    }
  }
}

foreach kb_key_pattern (data_protection::kb_scrub_list_emails)
{
  current_kb_list = get_kb_list(kb_key_pattern);
  if(!isnull(current_kb_list))
  {
    key_list = make_list(keys(current_kb_list));
    value_list = make_list(current_kb_list);
    max_index = max_index(key_list);
    for(i = 0; i < max_index; i++) 
    {
      kb_key = key_list[i];
      kb_value = value_list[i];
      sanitized = data_protection::sanitize_email_address_multiple(text:kb_value);
      if (kb_value != sanitized)
      {
        if(!isnull(sanitized))
        {
          rm_kb_item(name:kb_key, value:kb_value);
          set_kb_item(name:kb_key, value:sanitized);
        }
      }
    }
  }
}


foreach kb_key_pattern (data_protection::kb_scrub_list_ips)
{
  current_kb_list = get_kb_list(kb_key_pattern);
  if(!isnull(current_kb_list))
  {
    key_list = make_list(keys(current_kb_list));
    value_list = make_list(current_kb_list);
    max_index = max_index(key_list);
    for(i = 0; i < max_index; i++) 
    {
      kb_key = key_list[i];
      kb_value = value_list[i];
      sanitized = data_protection::sanitize_ip_address_multiple(text:kb_value);
      if (kb_value != sanitized)
      {
        if(!isnull(sanitized))
        {
          rm_kb_item(name:kb_key, value:kb_value);
          set_kb_item(name:kb_key, value:sanitized);
        }
      }
    }
  }
}

foreach kb_key_pattern (data_protection::kb_scrub_list_paths)
{
  current_kb_list = get_kb_list(kb_key_pattern);
  if(!isnull(current_kb_list))
  {
    key_list = make_list(keys(current_kb_list));
    value_list = make_list(current_kb_list);
    max_index = max_index(key_list);
    for(i = 0; i < max_index; i++) 
    {
      kb_key = key_list[i];
      kb_value = value_list[i];
      sanitized_key = data_protection::sanitize_user_paths(report_text:kb_key);
      sanitized_value = data_protection::sanitize_user_paths(report_text:kb_value);
      if (kb_key != sanitized_key || kb_value != sanitized_value)
      {
        if(!isnull(sanitized_key))
        {
          rm_kb_item(name:kb_key, value:kb_value);
          set_kb_item(name:sanitized_key, value:sanitized_value);
        }
      }
    }
  }
}

# Special checks: KB: www//*, check the value for " under ", path sanitize
www_kb_key_list = get_kb_list("www/*");
if(!isnull(www_kb_key_list))
{
  key_list = make_list(keys(www_kb_key_list));
  value_list = make_list(www_kb_key_list);
  max_index = max_index(key_list);
  for(i = 0; i < max_index; i++) 
  {
    www_kb_key = key_list[i];
    www_kb_value = value_list[i];
    if (preg(string:www_kb_value, pattern:" under ", multiline:TRUE))
    {
      sanitized = data_protection::sanitize_user_paths(report_text:www_kb_value);
      if (www_kb_value != sanitized)
      {
        if(!isnull(sanitized))
        {
          rm_kb_item(name:www_kb_key, value:www_kb_value);
          set_kb_item(name:www_kb_key, value:sanitized);
        }
      }
    }
  }
}

# Special checks: KB: "installed_sw/*" sanitize
installed_sw_kb_key_list = get_kb_list("installed_sw/*");
if(!isnull(installed_sw_kb_key_list))
{
  key_list = make_list(keys(installed_sw_kb_key_list));
  value_list = make_list(installed_sw_kb_key_list);
  max_index = max_index(key_list);
  for(i = 0; i < max_index; i++) 
  {
    kb_key = key_list[i];
    kb_value = value_list[i];
    sanitized = data_protection::sanitize_installed_sw(kb_key:kb_key);
    if (kb_key != sanitized)
    {
      if(!isnull(sanitized))
      {
        rm_kb_item(name:kb_key, value:kb_value);
        set_kb_item(name:sanitized, value:kb_value);
      }
    }
  }
}


##############
# SCRATCHPAD #
##############
#data_protection::scratchpad_scrub_list[tablename][field] = sanitize_type;

foreach table (keys(data_protection::scratchpad_scrub_list))
{
  # Skip tables that don't exist
  scratchpad_table_exists = query_scratchpad("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", table);
  if (isnull(scratchpad_table_exists))
  {
    continue;
  }
  foreach field (keys(data_protection::scratchpad_scrub_list[table]))
  { 
    values_list = query_scratchpad("SELECT DISTINCT " + field + " FROM " + table + ";");
    sanitize_type = data_protection::scratchpad_scrub_list[table][field];
    foreach value (values_list)
    {
      # values list entries are an array of field:value.
      value = value[field];
      sanitized = value;
      if (sanitize_type == "user" || sanitize_type == "password")
      {
        sanitized = data_protection::sanitize_userpass(text:value);
      }
      else if (sanitize_type == "email")
      {
        sanitized = data_protection::sanitize_email_address_multiple(text:value);
      }
      else if (sanitize_type == "phone")
      {
        sanitized = data_protection::sanitize_phone_numbers(text:value);
      }
      else if (sanitize_type == "path")
      {
        sanitized = data_protection::sanitize_user_paths(report_text:value);
      }
      else
      {
        # Unknown type, leave it as it is
        continue;
      }
      query_scratchpad("UPDATE " + table + " SET " + field + "=? WHERE " + field + "=?;", sanitized, value);
    }
  }
}

# Special checks: SCRATCHPAD: windows_env_vars: name (when it's "Path")
# Sanitize and update the "value"
scratchpad_table_exists = query_scratchpad("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", "windows_env_vars");
if (!isnull(scratchpad_table_exists))
{
  values_list = query_scratchpad("SELECT value FROM windows_env_vars WHERE name=?", "Path");
  foreach value (values_list)
  {
    value = value["value"];
    sanitized = data_protection::sanitize_user_paths(report_text:value);
    query_scratchpad("UPDATE windows_env_vars SET value=? WHERE name='Path' AND value=?;", sanitized, value);
  }
}
