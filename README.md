# wp-hack-fix
Script to resolve malware infections on WordPress websites by reinstalling all files on core, plugins and themes from their official repositories. Be aware: it removes anything it considers "non-core". Take a backup!

## Dependencies

`wp-cli` is required (available as `wp` command on your shell environment)

## How to use

From the WP root directory (where wp-blog-header.php resides) run:

```
curl -sO https://raw.githubusercontent.com/Pushkraj19/wp-hack-fix/master/wp-hack-fix.bash && bash wp-hack-fix.bash
```
