# rpsc - permissions and file types

## File types

When you run `ls -l`, each files are associated with a string of 10 letters like so:
```shell
$ ls -l
-rw-r--r--   ... Cargo.lock
-rw-r--r--   ... Cargo.toml
drwxr-xr-x   ... examples
-rw-r--r--   ... LICENSE-APACHE
-rw-r--r--   ... LICENSE-MIT
-rw-r--r--   ... README.md
drwxr-xr-x   ... src
drwxr-xr-x@  ... target
```
The first letter is the file type. You can search for files matching a certain type using the --type argument in rpsc:
```shell
$ rpsc --type d
target
examples
src
```
You can also specify the --type argument multiple times to return files of multiple types:
```shell
$ rpsc --type d --type -
Cargo.toml
LICENSE-APACHE
target
Cargo.lock
README.md
examples
LICENSE-MIT
src
```

## Permissions

The 9 other letters in the string are permissions. The first three are user permissions, and can be matched with the -u argument:
```shell
$ rpsc -u -rw
Cargo.toml
LICENSE-APACHE
Cargo.lock
README.md
LICENSE-MIT 
```

The next three are the group permissions and can be matched with the -g flag while the last three are the public permissions and can be matched with the -p flag.

