default['chef-squirrelmail']['squirrel_home'] = '/etc/squirrelmail'
default['chef-squirrelmail']['apache2_home'] = '/etc/apache2'
default['chef-squirrelmail']['site_name'] = 'webmail'
default['chef-squirrelmail']['site_home'] = '/usr/share/squirrelmail'
default['chef-squirrelmail']['data_home'] = '/usr/share/squirrelmail/data'
default['chef-squirrelmail']['apache_owner'] = 'www-data'
default['chef-squirrelmail']['apache_group'] = 'www-data'
default['chef-squirrelmail']['org_name'] = 'SquirrelMail'
default['chef-squirrelmail']['org_logo'] = 'images/sm_logo.png'
default['chef-squirrelmail']['org_logo_width'] = '308'
default['chef-squirrelmail']['org_logo_height'] = '111'
default['chef-squirrelmail']['org_title'] = 'SquirrelMail $version'
default['chef-squirrelmail']['signout_page'] = ''
default['chef-squirrelmail']['frame_top'] = '_top'
default['chef-squirrelmail']['provider_uri'] = 'http://squirrelmail.org/'
default['chef-squirrelmail']['provider_name'] = 'SquirrelMail'
default['chef-squirrelmail']['motd'] = ''
default['chef-squirrelmail']['squirrelmail_default_language'] = 'en_US'
default['chef-squirrelmail']['default_charset'] = 'iso-8859-1'
default['chef-squirrelmail']['lossy_encoding'] = 'false'
default['chef-squirrelmail']['domain'] = 'pf'
default['chef-squirrelmail']['imapServerAddress'] = 'localhost'
default['chef-squirrelmail']['imapPort'] = '143'
default['chef-squirrelmail']['useSendmail'] = 'false'
default['chef-squirrelmail']['smtpServerAddress'] = 'localhost'
default['chef-squirrelmail']['smtpPort'] = '25'
default['chef-squirrelmail']['sendmail_path'] = '/usr/sbin/sendmail'
default['chef-squirrelmail']['sendmail_args'] = '-i -t'
default['chef-squirrelmail']['pop_before_smtp'] = 'false'
default['chef-squirrelmail']['pop_before_smtp_host'] = ''
default['chef-squirrelmail']['imap_server_type'] = 'other'
default['chef-squirrelmail']['invert_time'] = 'false'
default['chef-squirrelmail']['optional_delimiter'] = 'detect'
default['chef-squirrelmail']['encode_header_key'] = ''
default['chef-squirrelmail']['default_folder_prefix'] = ''
default['chef-squirrelmail']['trash_folder'] = 'INBOX.Trash'
default['chef-squirrelmail']['sent_folder'] = 'INBOX.Sent'
default['chef-squirrelmail']['draft_folder'] = 'INBOX.Drafts'
default['chef-squirrelmail']['default_move_to_trash'] = 'true'
default['chef-squirrelmail']['default_move_to_sent'] = 'true'
default['chef-squirrelmail']['default_save_as_draft'] = 'true'
default['chef-squirrelmail']['show_prefix_option'] = 'false'
default['chef-squirrelmail']['list_special_folders_first'] = 'true'
default['chef-squirrelmail']['use_special_folder_color'] = 'true'
default['chef-squirrelmail']['auto_expunge'] = 'true'
default['chef-squirrelmail']['default_sub_of_inbox'] = 'true'
default['chef-squirrelmail']['show_contain_subfolders_option'] = 'false'
default['chef-squirrelmail']['default_unseen_notify'] = '2'
default['chef-squirrelmail']['default_unseen_type'] = '1'
default['chef-squirrelmail']['auto_create_special'] = 'true'
default['chef-squirrelmail']['delete_folder'] = 'false'
default['chef-squirrelmail']['noselect_fix_enable'] = 'false'
default['chef-squirrelmail']['data_dir'] = 'data/'
default['chef-squirrelmail']['attachment_dir'] = '$data_dir'
default['chef-squirrelmail']['dir_hash_level'] = '0'
default['chef-squirrelmail']['default_left_size'] = '150'
default['chef-squirrelmail']['force_username_lowercase'] = 'false'
default['chef-squirrelmail']['default_use_priority'] = 'true'
default['chef-squirrelmail']['hide_sm_attributions'] = 'false'
default['chef-squirrelmail']['default_use_mdn'] = 'true'
default['chef-squirrelmail']['edit_identity'] = 'true'
default['chef-squirrelmail']['edit_name'] = 'true'
default['chef-squirrelmail']['hide_auth_header'] = 'false'
default['chef-squirrelmail']['allow_thread_sort'] = 'false'
default['chef-squirrelmail']['allow_server_sort'] = 'false'
default['chef-squirrelmail']['allow_charset_search'] = 'true'
default['chef-squirrelmail']['uid_support'] = 'true'
default['chef-squirrelmail']['theme_css'] = ''
default['chef-squirrelmail']['theme_default'] = '43'
default['chef-squirrelmail']['default_use_javascript_addr_book'] = 'false'
default['chef-squirrelmail']['host'] = 'localhost'
default['chef-squirrelmail']['base'] = 'dc=squirrelmail,dc=org'
default['chef-squirrelmail']['name'] = '"LDAP: localhost"'
default['chef-squirrelmail']['port'] = '389'
default['chef-squirrelmail']['binddn'] = 'cn=userLDAP,dc=squirrelmail,dc=org'
default['chef-squirrelmail']['bindpw'] = 'password'
default['chef-squirrelmail']['protocol'] = 3
default['chef-squirrelmail']['abook_global_file'] = 'adressebook'
default['chef-squirrelmail']['abook_global_file_writeable'] = 'false'
default['chef-squirrelmail']['abook_global_file_listing'] = 'true'
default['chef-squirrelmail']['abook_file_line_length'] = '2048'
default['chef-squirrelmail']['config_location_base'] = ''