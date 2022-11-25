# rpsc - Associated owner and group

Running ls -l will list files along with their associated owner and group:
```shell
$ ls -l
-rw-r--r--   1 root  root   11742 Nov 24 09:21 Cargo.lock
-rw-r--r--   1 root  root     356 Nov 24 09:21 Cargo.toml
-rw-r--r--   1 root  root   10832 Nov 24 09:22 LICENSE-APACHE
-rw-r--r--   1 root  root    1072 Nov 24 09:22 LICENSE-MIT
-rw-r--r--   1 dev   staff   1524 Nov 24 09:27 README.md
drwxr-xr-x   3 dev   staff     96 Nov 24 09:34 examples
drwxr-xr-x   3 dev   staff     96 Nov 22 15:17 src
drwxr-xr-x@ 10 dev   staff    320 Nov 23 14:37 target
```

You can match the associated owner with rpsc and the --owner argument:
```shell
$ rpsc --owner dev
drwxr-xr-x dev staff target
.rw-r--r-- dev staff README.md
drwxr-xr-x dev staff examples
drwxr-xr-x dev staff src
```

You can also match the associated group with the --group argument (not supported on macOS!):
```shell
$ rpsc --group root
.rw-r--r-- root root Cargo.lock
.rw-r--r-- root root Cargo.toml
.rw-r--r-- root root LICENSE-APACHE
.rw-r--r-- root root LICENSE-MIT
```
