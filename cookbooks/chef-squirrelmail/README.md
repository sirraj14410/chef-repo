# chef-squirrelmail-cookbook

This cookbook install and configure the squirrelmail package.

## Supported Platforms

* DEBIAN 7.0.1

## Attributes

<table>
  <tr>
    <th>Key</th>
    <th>Type</th>
    <th>Description</th>
    <th>Default</th>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['squirrel_home']</tt></td>
    <td>String</td>
    <td>default config files</td>
    <td><tt>/etc/squirrelmail</tt></td>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['apache2_home']</tt></td>
    <td>String</td>
    <td>default config files for apache2</td>
    <td><tt>/etc/apache2</tt></td>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['site_name']</tt></td>
    <td>String</td>
    <td>name of the apache site web</td>
    <td><tt>webmail</tt></td>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['site_home']</tt></td>
    <td>String</td>
    <td>Path to the squirrelmail web site</td>
    <td><tt>/usr/share/squirrelmail</tt></td>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['data_home']</tt></td>
    <td>String</td>
    <td>Path to the squirrelmail users data</td>
    <td><tt>/usr/share/squirrelmail/data</tt></td>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['apache_owner']</tt></td>
    <td>String</td>
    <td>Owner of the apache user</td>
    <td><tt>www-data</tt></td>
  </tr>
  <tr>
    <td><tt>['chef-squirrelmail']['apache_group']</tt></td>
    <td>String</td>
    <td>Group of the apache user</td>
    <td><tt>www-data</tt></td>
  </tr>
</table>

See the default attribute file for more precisions.

## Usage

### chef-squirrelmail::default

Include `chef-squirrelmail` in your node's `run_list`:

```json
{
  "run_list": [
    "recipe[chef-squirrelmail::default]"
  ]
}
```

## License and Authors

Author : DSI (<stephane.lii@informatique.gov.pf>)
